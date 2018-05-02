using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Miracl;

namespace demo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            if (Client == null)
            {
                var options = new MiraclOptions
                {
                    ClientId = Environment.GetEnvironmentVariable("MFA_CLIENT_ID"),
                    ClientSecret = Environment.GetEnvironmentVariable("MFA_CLIENT_SECRET"),
                    SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                    // I'll leave this one here for now as a reminder for the system time "feature" of the windows containers
                    // TokenValidationParameters = new TokenValidationParameters { ValidateLifetime = false }, // not checking token lifetime for now, because windows containers have messed up system time
                    SaveTokens = true
                };

                Client = new MiraclClient(options);
            }
        }

        internal static MiraclClient Client;

        public static IConfiguration Configuration { get; private set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
