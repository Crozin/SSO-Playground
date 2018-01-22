using System.Security.Claims;
using System.Security.Principal;

namespace WebsiteSharedB
{
    public static class PrincipalExtensions
    {
        public static string GetName(this IPrincipal principal)
        {
            var cp = (ClaimsPrincipal) principal;

            return $"{cp.FindFirst("given_name").Value} {cp.FindFirst("family_name").Value}";
        }
    }
}