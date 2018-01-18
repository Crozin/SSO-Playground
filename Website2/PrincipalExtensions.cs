using System.Security.Claims;
using System.Security.Principal;

namespace Website2
{
    public static class PrincipalExtensions
    {
        public static string GetName(this IPrincipal principal)
        {
            var cp = (ClaimsPrincipal) principal;

            return $"{cp.FindFirst("sub").Value}";
        }
    }
}