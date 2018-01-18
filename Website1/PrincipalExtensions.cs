using System.Security.Claims;
using System.Security.Principal;

namespace Website1
{
    public static class PrincipalExtensions
    {
        public static string GetClaimValue(this IPrincipal principal, string claimType)
        {
            var cp = (ClaimsPrincipal) principal;

            return cp.FindFirst(claimType)?.Value;
        }

        public static string GetName(this IPrincipal principal)
        {
            return $"{principal.GetClaimValue("given_name")} {principal.GetClaimValue("family_name")}";
        }
    }
}