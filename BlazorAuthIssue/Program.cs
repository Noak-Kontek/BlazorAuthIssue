using BlazorAuthIssue.Components;
using BlazorAuthIssue.Components.Account;
using BlazorAuthIssue.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace BlazorAuthIssue
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();

            builder.Services.AddCascadingAuthenticationState();
            builder.Services.AddScoped<IdentityUserAccessor>();
            builder.Services.AddScoped<IdentityRedirectManager>();
            builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();
            builder.Services.AddScoped<IAuthorizationHandler, RequirementHandler>();

            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultScheme = IdentityConstants.ApplicationScheme;
                    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
                })
                .AddIdentityCookies();

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("GroupPolicy", policy =>
                {
                    policy.Requirements.Add(new Requirement()); // This is added to check Authorization

                });

            });

            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddIdentityCore<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddSignInManager()
                .AddDefaultTokenProviders();

            builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseAntiforgery();

            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            // Add additional endpoints required by the Identity /Account Razor components.
            app.MapAdditionalIdentityEndpoints();

            app.Run();
        }
    }

    public class RequirementHandler : AuthorizationHandler<Requirement>
    {
        private readonly NavigationManager _navigationManager;
        private readonly AuthenticationStateProvider _authenticationStateProvider;

        public RequirementHandler(NavigationManager navigationManager, AuthenticationStateProvider authenticationStateProvider)
        {
            _navigationManager = navigationManager;
            _authenticationStateProvider = authenticationStateProvider;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, Requirement requirement)
        {
            var groupId = ExtractIdFromUrl();
            var user = context.User;

            if (!string.IsNullOrEmpty(groupId) && user?.HasClaim("GroupId", groupId) == true)
            {
                context.Succeed(requirement);
            }

            await Task.CompletedTask;
        }

        private string? ExtractIdFromUrl()
        {
            var uri = _navigationManager.ToAbsoluteUri(_navigationManager.Uri);
            var segments = uri.Segments;

            if (segments.Length < 4)
                return null;

            var Id = segments[3].TrimEnd('/');
            return Id;
        }
    }

    public class Requirement : IAuthorizationRequirement { }
}
