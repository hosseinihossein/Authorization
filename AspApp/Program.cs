using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspApp.Helpers;
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



        //******************* Kestrel *******************
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, 80);
            options.Limits.MaxRequestBodySize = 16 * 1024;// 16 KB
        });



        //******************* Identity_DbContext *******************
        builder.Services.AddDbContext<Identity_DbContext>(options =>
        {
            options.UseNpgsql(builder.Configuration["Postgres:ConnectionString:Identity"]);
            options.UseOpenIddict<Guid>();
        });
        //******************* DataProtection_DbContext *******************
        builder.Services.AddDbContext<DataProtection_DbContext>(options =>
        {
            options.UseNpgsql(builder.Configuration["Postgres:ConnectionString:DataProtection"]);
        });



        //******************* Identity service *******************
        builder.Services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
        {
            options.User.AllowedUserNameCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

            options.User.RequireUniqueEmail = true;

            options.SignIn.RequireConfirmedEmail = false;

            options.Password.RequireDigit = false;
            options.Password.RequiredLength = 8;
            options.Password.RequireLowercase = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequiredUniqueChars = 1;
        })
        .AddEntityFrameworkStores<Identity_DbContext>()
        .AddDefaultTokenProviders();


        //******************* identity cookie *******************
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true; // prevent from js access
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // https only
            options.Cookie.SameSite = SameSiteMode.Lax;// protect unsafe methods from csrf
            options.Cookie.Path = "/api/identity/";

            //Default for "Remember Me". Without "Remember Me" → Session cookie (expires when browser closes)
            options.ExpireTimeSpan = TimeSpan.FromDays(14);//null or don't set for session lifetime
            options.SlidingExpiration = true;//Reset expiration when user interacts halfway through the lifespan

            options.LoginPath = "/Authentication";
            //options.AccessDeniedPath = "/Account/AccessDenied";
        });


        //******************* Data Protection *******************
        // Configure shared Data Protection keys in SQL DB
        builder.Services.AddDataProtection()
        .PersistKeysToDbContext<DataProtection_DbContext>() // Store keys in the same DB
        .SetApplicationName("SharedIdentityApp"); // Must match across all servers


        //******************* SecurityStampValidatorOptions *******************
        builder.Services.Configure<SecurityStampValidatorOptions>(options =>
        {
            options.ValidationInterval = TimeSpan.Zero;
        });



        // Quartz
        builder.Services.AddQuartz(options =>
        {
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });
        builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);


        // **********    CertManager    **********
        CertManager certManager = new(builder.Environment);
        builder.Services.AddSingleton<CertManager>(certManager);


        // OpenIddict
        builder.Services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
            .UseDbContext<Identity_DbContext>()
            .ReplaceDefaultEntities<Guid>();

            options.UseQuartz();
        })
        .AddServer(async options =>
        {
            options.SetAuthorizationEndpointUris("/api/identity/Authorization/Authorize")
            .SetEndSessionEndpointUris("/api/identity/Authorization/Logout")
            .SetTokenEndpointUris("/api/identity/Authorization/Token")
            .SetUserInfoEndpointUris("/api/identity/Authorization/UserInfo");
            //.SetJsonWebKeySetEndpointUris(builder.Configuration["OidcIssuer"]+"/.well-known/jwks")
            //.SetIssuer(builder.Configuration["MyAppDomain"]!);

            options.RegisterScopes(Scopes.Email, Scopes.Roles);

            options.AllowClientCredentialsFlow()
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow();

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
            X509Certificate2 ecdsaSigningCert = await certManager.GetEcdsaSigningCert();
            // Extract the ECDSA key and pass it as a raw signing key
            if (ecdsaSigningCert.GetECDsaPrivateKey() is ECDsa ecdsaKey)
            {
                options.AddSigningKey(new ECDsaSecurityKey(ecdsaKey));
            }
            else
            {
                throw new Exception("Invalid certificate type for oidc signing: Expected an ECDSA PFX file.");
            }

            options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableStatusCodePagesIntegration()
            .DisableTransportSecurityRequirement();

            options.RequireProofKeyForCodeExchange();//enables globally

            options.SetAccessTokenLifetime(TimeSpan.FromHours(1));
            options.SetIdentityTokenLifetime(TimeSpan.FromHours(1));
            options.SetRefreshTokenLifetime(TimeSpan.FromDays(14));
        });


        //******************* ControllersWithViews *******************
        builder.Services.AddControllers();


        //******************* AntiForgery *******************
        builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            //options.Cookie.Name = "XSRF-TOKEN";//swap error
        });


        //**************************** Kafka Producer **************************
        KafkaProducerService kafkaService = new(builder.Configuration);
        builder.Services.AddSingleton<KafkaProducerService>(kafkaService);


        //**************************** Logger **************************
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(); // Keep Console for local visibility
        builder.Logging.AddKafka(kafkaService, builder.Configuration);


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

            if (await appManager.FindByClientIdAsync("HoLibz_Angular_App") is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "HoLibz_Angular_App",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "HoLibz Angular Client Application",
                    ClientType = ClientTypes.Public,
                    PostLogoutRedirectUris =
                    {
                        new Uri(builder.Configuration["HostName"] + "/")
                    },
                    RedirectUris =
                    {
                        new Uri(builder.Configuration["HostName"] + "/")
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
                    /*Requirements =// globally set at server configs
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    },*/
                });
            }
        }


        //******************* app.Run ******************
        Console.WriteLine($"\n*** App is running on all network, port '80'");
        app.Run();
    }
}
