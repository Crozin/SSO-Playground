using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services.InMemory;

namespace IdentityServer.Services
{
    public class CustomUserService : InMemoryUserService
    {
        public CustomUserService(List<InMemoryUser> users) : base(users) { }

        public override async Task PreAuthenticateAsync(PreAuthenticationContext context)
        {
            await base.PreAuthenticateAsync(context);
        }

        public override async Task AuthenticateLocalAsync(LocalAuthenticationContext context)
        {
            await base.AuthenticateLocalAsync(context);

            if (context.AuthenticateResult != null)
            {
                var sub = context.AuthenticateResult.User.FindFirst("sub")?.Value;

                if (sub == "2")
                {
                    //                        var code = await this.userManager.GenerateTwoFactorTokenAsync(id, "sms");
                    //                        var result = await userManager.NotifyTwoFactorTokenAsync(id, "sms", code);

                    //                        if (!result.Succeeded)
                    //                        {
                    //                            context.AuthenticateResult = new AuthenticateResult(result.Errors.First());
                    //                        }

                    context.AuthenticateResult = new AuthenticateResult("~/TwoFactor", sub, sub);
                }
            }
        }

        public override async Task PostAuthenticateAsync(PostAuthenticationContext context)
        {
            await base.PostAuthenticateAsync(context);
        }
    }
}