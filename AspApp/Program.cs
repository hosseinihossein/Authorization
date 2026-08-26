using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using AspApp.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AspApp;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);



        string certsDirPath = Path.Combine(builder.Environment.ContentRootPath, "Certs");
        Directory.CreateDirectory(certsDirPath);

        //****************** Certificates ****************
        // Server signing
        /*string serverSigningCertPath = Path.Combine(certsDirPath, "oidc-server-signing-certificate.pfx");
        X509Certificate2 serverSigningCert;
        if (File.Exists(serverSigningCertPath))
        {
            serverSigningCert = X509CertificateLoader.LoadPkcs12FromFile(serverSigningCertPath, string.Empty);
        }*/
        /*else
        {
            using var algorithm = RSA.Create(keySizeInBits: 4096);

            var subject = new X500DistinguishedName("CN=OIDC Server Signing Certificate");
            var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

            serverSigningCert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));

            await File.WriteAllBytesAsync(serverSigningCertPath, serverSigningCert.Export(X509ContentType.Pfx, string.Empty));
        }*/
        /*else
        {
            // 1. Create an ECDSA key pair
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // 2. Define certificate subject
            var subject = new X500DistinguishedName("CN=OIDC Server Signing Certificate");

            // 3. Create certificate request
            var request = new CertificateRequest(
                subject,
                ecdsa,
                HashAlgorithmName.SHA256
            );

            // Optional: Add extensions
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false)
            );
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature,// | X509KeyUsageFlags.KeyEncipherment,
                    critical: false
                )
            );
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false)
            );

            serverSigningCert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(1)
            );

            await File.WriteAllBytesAsync(serverSigningCertPath, serverSigningCert.Export(X509ContentType.Pfx, string.Empty));

        }*/



        //******************* Kestrel *******************
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, 80);
            options.Limits.MaxRequestBodySize = 16 * 1024;// 16 KB
        });



        // Identity DbContext
        builder.Services.AddDbContext<Identity_DbContext>(options =>
        {
            options.UseNpgsql(builder.Configuration["ConnectionStrings_Postgres:IdentityConnection"]);

            options.UseOpenIddict<Guid>();
        });

        // DataProtection DbContext
        builder.Services.AddDbContext<DataProtection_DbContext>(options =>
        {
            options.UseNpgsql(builder.Configuration["ConnectionStrings_Postgres:DataProtectionConnection"]);
        });



        // Identity
        builder.Services.AddIdentity<Identity_UserDbModel, Identity_RoleDbModel>(options =>
        {
            options.User.AllowedUserNameCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

            options.User.RequireUniqueEmail = true;

            options.SignIn.RequireConfirmedEmail = false;

            options.Password.RequireDigit = false;
            options.Password.RequiredLength = 5;
            options.Password.RequireLowercase = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequiredUniqueChars = 1;
        })
        .AddEntityFrameworkStores<Identity_DbContext>()
        .AddDefaultTokenProviders();



        //******************* config identity cookie *******************
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true; // prevent from js access
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // https only
            options.Cookie.SameSite = SameSiteMode.None;// no csrf protection to solve strict tracking prevention mechanisms

            //Default for "Remember Me". Without "Remember Me" → Session cookie (expires when browser closes)
            options.ExpireTimeSpan = TimeSpan.FromDays(14);
            options.SlidingExpiration = true;

            options.LoginPath = "/Authentication";
            //options.AccessDeniedPath = "/Account/AccessDenied";
        });

        //******************* SecurityStampValidatorOptions *******************
        builder.Services.Configure<SecurityStampValidatorOptions>(options =>
        {
            options.ValidationInterval = TimeSpan.Zero;
        });



        //******************* Data Protection *******************
        // Configure shared Data Protection keys in SQL DB
        builder.Services.AddDataProtection()
        .PersistKeysToDbContext<DataProtection_DbContext>() // Store keys in the same DB
        .SetApplicationName("SharedIdentityApp"); // Must match across all servers



        // Quartz
        builder.Services.AddQuartz(options =>
        {
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });
        builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);



        // OpenIddict
        builder.Services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
            .UseDbContext<Identity_DbContext>()
            .ReplaceDefaultEntities<Guid>();

            options.UseQuartz();
        })
        .AddServer(options =>
        {
            options.SetAuthorizationEndpointUris("/Api/Authorization/Authorize")
            .SetEndSessionEndpointUris("/Api/Authorization/Logout")
            .SetTokenEndpointUris("/Api/Authorization/Token")
            .SetUserInfoEndpointUris("/Api/Authorization/UserInfo")
            //.SetJsonWebKeySetEndpointUris(builder.Configuration["OidcIssuer"]+"/.well-known/jwks")
            .SetIssuer(builder.Configuration["MyAppDomain"]!);

            options.RegisterScopes(Scopes.Email, Scopes.Roles);

            options.AllowClientCredentialsFlow()
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow();

            //options.AddDevelopmentEncryptionCertificate()
            // Register the encryption credentials. This sample uses a symmetric
            // encryption key that is shared between the server and the API project.
            //
            // Note: in a real world application, this encryption key should be
            // stored in a safe place (e.g in Azure KeyVault, stored as a secret).
            options.AddEncryptionKey(new SymmetricSecurityKey(
                Convert.FromBase64String(builder.Configuration["OidcServerEncryptionKey"]!)
            ));
            //options.DisableAccessTokenEncryption();//throws exception
            //options.AddDevelopmentEncryptionCertificate();

            //options.AddSigningCertificate(serverSigningCert);
            //options.AddSigningCredentials(new X509SigningCredentials(serverSigningCert, SecurityAlgorithms.EcdsaSha256));
            options.AddSigningCredentials(new SigningCredentials(
                new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)),
                SecurityAlgorithms.EcdsaSha256   
            ));
            //options.AddSigningKey()

            options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableStatusCodePagesIntegration()
            .DisableTransportSecurityRequirement();

            options.RequireProofKeyForCodeExchange();//enables globally

            options.SetAccessTokenLifetime(TimeSpan.FromHours(10));
            options.SetIdentityTokenLifetime(TimeSpan.FromHours(10));
            options.SetRefreshTokenLifetime(TimeSpan.FromDays(14));
        });



        //******************* ControllersWithViews *******************
        builder.Services.AddControllersWithViews();



        var app = builder.Build();



        app.UseForwardedHeaders(new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            KnownIPNetworks = { new System.Net.IPNetwork(IPAddress.Parse("172.18.0.0"), 16) }
        });



        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
        app.MapDefaultControllerRoute();



        await using (var scope = app.Services.CreateAsyncScope())
        {
            // ***** Angular app *****
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await appManager.FindByClientIdAsync("NewUserProfileApp_01") is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "NewUserProfileApp_01",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "User Profile Angular Client Application",
                    ClientType = ClientTypes.Public,
                    PostLogoutRedirectUris =
                    {
                        new Uri(builder.Configuration["MyAppDomain"] + "/UserProfile")
                    },
                    RedirectUris =
                    {
                        new Uri(builder.Configuration["MyAppDomain"] + "/UserProfile")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        //Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    },
                });
            }
            var myClientApp = await appManager.FindByClientIdAsync("NewUserProfileApp_01");
            if(myClientApp is not null && myClientApp is OpenIddictApplicationDescriptor)
            {
                foreach (var ruri in ((OpenIddictApplicationDescriptor)myClientApp).RedirectUris)
                {
                    Console.WriteLine("\n***** ruri= " + ruri);
                }
            }
            else
            {
                string json = JsonSerializer.Serialize(myClientApp);
                Console.WriteLine("\n***** myClientApp json= " + json);
            }
        }


        //******************* app.Run ******************
        //Console.WriteLine($"\n*** App is running on all network interfaces on port '{builder.Configuration["TcpPort"]}'");
        Console.WriteLine($"\n*** App is running on all network, port '80'");
        app.Run();
    }
}
