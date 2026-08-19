using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspApp.Models;
using Microsoft.AspNetCore.DataProtection;
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
        string serverSigningCertPath = Path.Combine(certsDirPath, "oidc-server-signing-certificate.pfx");
        X509Certificate2 serverSigningCert;
        if (File.Exists(serverSigningCertPath))
        {
            serverSigningCert = X509CertificateLoader.LoadPkcs12FromFile(serverSigningCertPath, string.Empty);
        }
        /*else
        {
            using var algorithm = RSA.Create(keySizeInBits: 4096);

            var subject = new X500DistinguishedName("CN=OIDC Server Signing Certificate");
            var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

            serverSigningCert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

            await File.WriteAllBytesAsync(serverSigningCertPath, serverSigningCert.Export(X509ContentType.Pfx, string.Empty));
        }*/
        else
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

        }



        //******************* Kestrel *******************
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, builder.Configuration.GetValue<int>("TcpPort"), listenOptions =>
            {
                string pemFilePath = Path.Combine(certsDirPath, "HoLibz.com.pem");
                string keyFilePath = Path.Combine(certsDirPath, "HoLibz.com.key");
                if (System.IO.File.Exists(pemFilePath) && System.IO.File.Exists(keyFilePath))
                {
                    X509Certificate2 x509Certificate2 = X509Certificate2.CreateFromPemFile(pemFilePath, keyFilePath);
                    listenOptions.UseHttps(x509Certificate2);
                }
                else
                {
                    listenOptions.UseHttps();
                }
            });

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

            //options.LoginPath = "/Account/Login";
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
            options.SetAuthorizationEndpointUris("Authorization/Api/Authorize")
            .SetEndSessionEndpointUris("Authorization/Api/Logout")
            .SetTokenEndpointUris("Authorization/Api/Token")
            .SetUserInfoEndpointUris("Authorization/Api/UserInfo");

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

            //options.AddSigningCertificate(serverSigningCert);
            options.AddSigningCredentials(new X509SigningCredentials(serverSigningCert));

            options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

            options.RequireProofKeyForCodeExchange();//enables globally

            options.SetAccessTokenLifetime(TimeSpan.FromHours(10));
            options.SetIdentityTokenLifetime(TimeSpan.FromHours(10));
            options.SetRefreshTokenLifetime(TimeSpan.FromDays(14));
        });



        //******************* ControllersWithViews *******************
        builder.Services.AddControllersWithViews(options =>
        {
            options.Filters.Add(new RequireHttpsAttribute());
        });



        //******************* AntiForgery *******************
        /*builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            //options.Cookie.Name = "XSRF-TOKEN";//swap error
        });*/



        //******************* IHttpClientFactory *******************
        //builder.Services.AddHttpClient();



        //**************************** Custom Services **************************
        builder.Services.AddSingleton<FileExtensionContentTypeProvider>();



        if (builder.Environment.IsDevelopment())
        {
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigin", policy =>
                {
                    policy.WithOrigins("https://localhost:5444", "https://localhost:5445")
                    .AllowAnyHeader()
                    .AllowAnyMethod();
                });
            });
        }



        var app = builder.Build();



        if (builder.Environment.IsDevelopment())
        {
            app.UseCors("AllowSpecificOrigin");
        }



        app.UseHttpsRedirection();
        app.UseStaticFiles(new StaticFileOptions { ServeUnknownFileTypes = true });
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
        app.MapDefaultControllerRoute();

        app.Map("/{*catchAll}", async (HttpContext context, FileExtensionContentTypeProvider provider) =>
        {
            string? catchAll = context.Request.RouteValues["catchAll"]?.ToString();
            if (!string.IsNullOrWhiteSpace(catchAll))
            {
                string staticFilePath =
                Path.Combine(app.Environment.WebRootPath, "AngularApp", "browser", catchAll);
                if (File.Exists(staticFilePath))
                {
                    //var provider = new FileExtensionContentTypeProvider();
                    if (provider.TryGetContentType(staticFilePath, out string? contentType))
                    {
                        context.Response.ContentType = contentType;
                        await context.Response.SendFileAsync(staticFilePath);
                        return;
                    }
                    else
                    {
                        context.Response.ContentType = "application/octet-stream";
                        await context.Response.SendFileAsync(staticFilePath);
                        return;
                    }
                }
            }

            context.Response.ContentType = "text/html";
            await context.Response.SendFileAsync(
                Path.Combine(app.Environment.WebRootPath, "AngularApp", "browser", "index.html")
            );
        });



        await using (var scope = app.Services.CreateAsyncScope())
        {
            // ***** Angular app *****
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await appManager.FindByClientIdAsync("UserProfileApp") is null)
            {
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "UserProfileApp",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "User Profile Angular Client Application",
                    ClientType = ClientTypes.Public,
                    PostLogoutRedirectUris =
                    {
                        new Uri("https://localhost:5445")
                    },
                    RedirectUris =
                    {
                        new Uri("https://localhost:5445")
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
        }


        //******************* app.Run ******************
        Console.WriteLine($"\n*** App is running on all network interfaces on port '{builder.Configuration["TcpPort"]}'");
        app.Run();
    }
}
