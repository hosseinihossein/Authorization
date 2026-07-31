using System.Security.Claims;
using System.Text.Json;
using AspApp.Helpers;
using AspApp.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AspApp.Controllers;

//[ApiController]
//[Route("Identity/Api/[controller]/[action]")]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<Identity_UserDbModel> _userManager;
    private readonly SignInManager<Identity_UserDbModel> _signInManager;



    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<Identity_UserDbModel> userManager,
        SignInManager<Identity_UserDbModel> signInManager
    )
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
        _signInManager = signInManager;
    }



    [HttpGet("~/Authorization/Api/Authorize")]
    [HttpPost("~/Authorization/Api/Authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var openIddictRequest = HttpContext.GetOpenIddictServerRequest();
        if (openIddictRequest is null)
        {
            ModelState.AddModelError("Request", "The OpenID Connect request cannot be retrieved.");
            return BadRequest(ModelState);
        }

        // Try to retrieve the user principal stored in the authentication cookie and redirect
        // the user agent to the login page (or to an external provider) in the following cases:
        //
        //  - If the user principal can't be extracted or the cookie is too old.
        //  - If prompt=login was specified by the client application.
        //  - If max_age=0 was specified by the client application (max_age=0 is equivalent to prompt=login).
        //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
        //
        // For scenarios where the default authentication handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        var authResult = await HttpContext.AuthenticateAsync();

        if (!authResult.Succeeded ||
        (openIddictRequest.HasPromptValue(PromptValues.Login) ||
         openIddictRequest.MaxAge is 0 ||
         (openIddictRequest.MaxAge is not null && authResult.Properties?.IssuedUtc is not null &&
          TimeProvider.System.GetUtcNow() - authResult.Properties.IssuedUtc > TimeSpan.FromSeconds(openIddictRequest.MaxAge.Value)
         )
        ))
        {
            // If the client application requested promptless authentication,
            // return an error indicating that the user is not logged in.
            if (openIddictRequest.HasPromptValue(PromptValues.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    })
                );
            }

            // To avoid endless login endpoint -> authorization endpoint redirects, a special temp data entry is
            // used to skip the challenge if the user agent has already been redirected to the login endpoint.
            //
            // Note: this flag doesn't guarantee that the user has accepted to re-authenticate. If such a guarantee
            // is needed, the existing authentication cookie MUST be deleted AND revoked (e.g using ASP.NET Core
            // Identity's security stamp feature with an extremely short revalidation time span) before triggering
            // a challenge to redirect the user agent to the login endpoint.
            //TempData["IgnoreAuthenticationChallenge"] = true;

            // For scenarios where the default challenge handler configured in the ASP.NET Core
            // authentication options shouldn't be used, a specific scheme can be specified here.

            string myUrl = /*Request.Scheme + "://" + Request.Host + */Request.PathBase + Request.Path +
            QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query);
            //Console.WriteLine($"\n***** myUrl = {myUrl}");

            return Challenge(new AuthenticationProperties
            {
                RedirectUri = myUrl,
            });
        }
        //Console.WriteLine($"\n***** Cookies = {JsonSerializer.Serialize(Request.Cookies.ToDictionary())}");

        // Retrieve the profile of the logged in user.
        var user = await _userManager.GetUserAsync(authResult.Principal);
        if (user is null)
        {
            ModelState.AddModelError("User", "The user details cannot be retrieved.");
            return BadRequest(ModelState);
        }

        // Retrieve the application details from the database.
        var application = await _applicationManager.FindByClientIdAsync(openIddictRequest.ClientId!);
        if (application is null)
        {
            ModelState.AddModelError("application", "Details concerning the calling client application cannot be found.");
            return BadRequest(ModelState);
        }

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: openIddictRequest.GetScopes()
        ).ToListAsync();

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            // If the consent is external (e.g when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database.
            case ConsentTypes.External when authorizations.Count is 0:
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application.",
                    })
                );

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count is not 0:
            case ConsentTypes.Explicit when authorizations.Count is not 0 &&
            !openIddictRequest.HasPromptValue(PromptValues.Consent):
                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var claimsIdentity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType/*,
                    nameType: Claims.Name,
                    roleType: Claims.Role*/
                );

                // Add the claims that will be persisted in the tokens.
                claimsIdentity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.EmailVerified, await _userManager.IsEmailConfirmedAsync(user))
                //.SetClaim(Claims.Username, await _userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await _userManager.GetRolesAsync(user)]);
                //.SetClaim(Claims.Name, user.DisplayName)
                //.SetClaim("description", user.Description)
                //.SetClaim("public_email", user.PublicEmail)
                //.SetClaim("image_version", user.ImageVersion)
                //.SetClaim("has_image", user.HasImage)
                //.SetClaim("remote_image", user.RemoteImageUrl)
                //.SetClaim("created_at", user.CreatedAt);

                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.
                claimsIdentity.SetScopes(openIddictRequest.GetScopes());
                claimsIdentity.SetResources(await _scopeManager
                    .ListResourcesAsync(claimsIdentity.GetScopes())
                    .ToListAsync()
                );

                // Automatically create a permanent authorization to avoid requiring explicit consent
                // for future authorization or token requests containing the same scopes.
                var authorization = authorizations.LastOrDefault();
                authorization ??= await _authorizationManager.CreateAsync(
                    identity: claimsIdentity,
                    subject: await _userManager.GetUserIdAsync(user),
                    client: (await _applicationManager.GetIdAsync(application))!,
                    type: AuthorizationTypes.Permanent,
                    scopes: claimsIdentity.GetScopes()
                );

                claimsIdentity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                claimsIdentity.SetDestinations(GetDestinations);

                return SignIn(new ClaimsPrincipal(claimsIdentity),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit when openIddictRequest.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when openIddictRequest.HasPromptValue(PromptValues.None):
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    })
                );

            // In every other case, render the consent form.
            default:
                string redirectUri = "/Authorize/Consent" +
                QueryString.Create(Request.HasFormContentType ? Request.Form : Request.Query);
                return Redirect(redirectUri);
        }
    }



    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost("~/Authorization/Api/Authorize")/*, ValidateAntiForgeryToken*/]
    public async Task<IActionResult> Accept()
    {
        var openIddictRequest = HttpContext.GetOpenIddictServerRequest();
        if (openIddictRequest is null)
        {
            ModelState.AddModelError("Request", "The OpenID Connect request cannot be retrieved.");
            return BadRequest(ModelState);
        }

        // Retrieve the profile of the logged in user.
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Forbid();
        }

        // Retrieve the application details from the database.
        var application = await _applicationManager.FindByClientIdAsync(openIddictRequest.ClientId!);
        if (application is null)
        {
            ModelState.AddModelError("application", "Details concerning the calling client application cannot be found.");
            return BadRequest(ModelState);
        }

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: openIddictRequest.GetScopes()
        ).ToListAsync();

        // Note: the same check is already made in the other action but is repeated
        // here to ensure a malicious user can't abuse this POST-only endpoint and
        // force it to return a valid response without the external authorization.
        if (authorizations.Count is 0 &&
            await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                })
            );
        }

        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var claimsIdentity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType/*,
            nameType: Claims.Name,
            roleType: Claims.Role*/
        );

        // Add the claims that will be persisted in the tokens.
        claimsIdentity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
        .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
        .SetClaim(Claims.EmailVerified, await _userManager.IsEmailConfirmedAsync(user))
        //.SetClaim(Claims.Username, await _userManager.GetUserNameAsync(user))
        .SetClaims(Claims.Role, [.. await _userManager.GetRolesAsync(user)]);

        // Note: in this sample, the granted scopes match the requested scope
        // but you may want to allow the user to uncheck specific scopes.
        // For that, simply restrict the list of scopes before calling SetScopes.
        claimsIdentity.SetScopes(openIddictRequest.GetScopes());
        claimsIdentity.SetResources(await _scopeManager.ListResourcesAsync(claimsIdentity.GetScopes()).ToListAsync());

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: claimsIdentity,
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: claimsIdentity.GetScopes()
        );

        claimsIdentity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        claimsIdentity.SetDestinations(GetDestinations);

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        return SignIn(new ClaimsPrincipal(claimsIdentity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }



    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost("~/Authorization/Api/Authorize")/*, ValidateAntiForgeryToken*/]
    // Notify OpenIddict that the authorization grant has been denied by the resource owner
    // to redirect the user agent to the client application using the appropriate response_mode.
    public async Task<IActionResult> Deny() //=> Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    {
        await _signInManager.SignOutAsync();
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            }
        );
    }



    [Authorize]
    [HttpGet("~/Authorization/Api/Logout")]
    public async Task<IActionResult> Logout()
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow (e.g Google or Facebook).
        //Console.WriteLine($"\n*** before signout: {User.Identity?.IsAuthenticated} ***");
        await _signInManager.SignOutAsync();
        //Console.WriteLine($"\n*** after signout: {User.Identity?.IsAuthenticated} ***");

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            }
        );
    }



    [Authorize]
    [/*ActionName(nameof(Logout)),*/ HttpPost("~/Authorization/Api/Logout")/*, ValidateAntiForgeryToken*/]
    public async Task<IActionResult> LogoutPost()
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow (e.g Google or Facebook).
        //Console.WriteLine($"\n*** before signout: {User.Identity?.IsAuthenticated} ***");
        await _signInManager.SignOutAsync();
        //Console.WriteLine($"\n*** after signout: {User.Identity?.IsAuthenticated} ***");

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            }
        );
    }



    [HttpPost("~/Authorization/Api/Token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var openIddictRequest = HttpContext.GetOpenIddictServerRequest();
        if (openIddictRequest is null)
        {
            ModelState.AddModelError("Request", "The OpenID Connect request cannot be retrieved.");
            return BadRequest(ModelState);
        }

        if (openIddictRequest.IsAuthorizationCodeGrantType() || openIddictRequest.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the authorization code/refresh token.
            var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Retrieve the user profile corresponding to the authorization code/refresh token.
            var user = await _userManager.FindByIdAsync(authResult.Principal!.GetClaim(Claims.Subject)!);
            if (user is null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The token is no longer valid.",
                    })
                );
            }

            // Ensure the user is still allowed to sign in.
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user is no longer allowed to sign in.",
                    })
                );
            }

            var claimsIdentity = new ClaimsIdentity(authResult.Principal!.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType/*,
                nameType: Claims.Name,
                roleType: Claims.Role*/
            );

            // Override the user claims present in the principal in case they
            // changed since the authorization code/refresh token was issued.
            claimsIdentity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
            .SetClaim(Claims.EmailVerified, await _userManager.IsEmailConfirmedAsync(user))
            //.SetClaim(Claims.Username, await _userManager.GetUserNameAsync(user))
            .SetClaims(Claims.Role, [.. await _userManager.GetRolesAsync(user)]);

            claimsIdentity.SetDestinations(GetDestinations);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(claimsIdentity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (openIddictRequest.IsClientCredentialsGrantType())
        {
            // Note: the client credentials are automatically validated by OpenIddict:
            // if client_id or client_secret are invalid, this action won't be invoked.

            var application = await _applicationManager.FindByClientIdAsync(openIddictRequest.ClientId!);
            if (application is null)
            {
                ModelState.AddModelError("application", "Details concerning the calling client application cannot be found.");
                return BadRequest(ModelState);
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code. 
            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType,
                Claims.Name,
                Claims.Role
            );

            // Use the client_id as the subject identifier.
            identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
            identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        ModelState.AddModelError("GrantType", "The specified grant type is not supported.");
        return BadRequest(ModelState);
    }



    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            /*case Claims.Username or Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;*/

            case Claims.Email or Claims.EmailVerified:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject!.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }


}