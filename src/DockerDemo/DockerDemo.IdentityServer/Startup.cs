using System;
using System.Reflection;
using DockerDemo.IdentityServer.Abstractions;
using DockerDemo.IdentityServer.Infrastructure;
using DockerDemo.IdentityServer.Services;
using FluentValidation.AspNetCore;
using IdentityServer4.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;

namespace DockerDemo.IdentityServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }


        public IWebHostEnvironment Environment { get; }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddOptions();

            var mvcBuilder = services.AddControllersWithViews()
                .AddFluentValidation(fv =>
                {
                    fv.LocalizationEnabled = true;
                    fv.ImplicitlyValidateChildProperties = true;
                    fv.RunDefaultMvcValidationAfterFluentValidationExecutes = true;
                    fv.RegisterValidatorsFromAssemblyContaining<IUserValidator<IdentityUser>>();
                });

            var connectionString = Configuration.GetConnectionString("IdentityServer");
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            services.AddDbContext<IdentityContext>(options =>
                options.UseNpgsql(connectionString));

            services.AddIdentity<IdentityUser, IdentityRole>(options =>
                {
                    options.Password.RequireDigit = true;
                    options.Password.RequireLowercase = true;
                    options.Password.RequireNonAlphanumeric = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequiredLength = 6;

                    options.SignIn.RequireConfirmedEmail = true;

                    options.User.RequireUniqueEmail = true;
                })
                .AddEntityFrameworkStores<IdentityContext>()
                .AddDefaultTokenProviders();

            var builder = services.AddIdentityServer(options =>
                {
                    options.IssuerUri = Configuration.GetValue<string>("Host");
                    options.Events.RaiseErrorEvents = true;
                    options.Events.RaiseInformationEvents = true;
                    options.Events.RaiseFailureEvents = true;
                    options.Events.RaiseSuccessEvents = true;

                    options.Authentication = new AuthenticationOptions
                    {
                        CookieLifetime = TimeSpan.FromSeconds(1800),
                        CookieSlidingExpiration = true,
                        RequireAuthenticatedUserForSignOutMessage = true
                    };
                })
                .AddTestUsers(Config.GetUsers())
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseNpgsql(connectionString,
                            sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseNpgsql(connectionString,
                            sql => sql.MigrationsAssembly(migrationsAssembly));

                    options.EnableTokenCleanup = true;
                })

                //.AddInMemoryClients(Configuration.GetSection("IdentityServer:Clients"))
                .AddAspNetIdentity<IdentityUser>();

            // TODO: Удалить после того как сделают сертификат
            builder.AddDeveloperSigningCredential();

            if (Environment.IsDevelopment())
            {
                // TODO: Раскомментировать после того как сделают сертификат
                // builder.AddDeveloperSigningCredential();

                mvcBuilder
                    .AddRazorRuntimeCompilation();
            }

            services.AddAuthentication()
                .AddCookie(x => { x.Cookie.SecurePolicy = CookieSecurePolicy.None; });
            services.AddHostedService<InitializeDatabaseService>();

            services.AddScoped<ISignInManager, SignInManager>();
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<IUserManager, UserManager>();

            services.AddSession();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseForwardedHeaders();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
                app.UseHttpsRedirection();
                app.UseExceptionHandler("/Home/Error");

                app.Use((context, next) =>
                {
                    context.Request.Scheme = "https";

                    return next();
                });
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthorization();
            app.UseAuthentication();
            app.UseIdentityServer();

            app.UseEndpoints(endpoints => { endpoints.MapDefaultControllerRoute(); });
        }
    }
}