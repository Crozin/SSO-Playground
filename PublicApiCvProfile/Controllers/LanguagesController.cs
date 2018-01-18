using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;
using IdentityModel;

namespace PublicApiCvProfile.Controllers
{
    [RoutePrefix("languages")]
    public class LanguagesController : ApiController
    {
        private static ConcurrentDictionary<string, List<string>> Database { get; } = new ConcurrentDictionary<string, List<string>>();

        [HttpGet, Route, ClaimsAuthorize(new[] { "api_cv_profile:read" })]
        public ICollection<string> List()
        {
            var cp = (ClaimsPrincipal) User;

            return Database.GetOrAdd(cp.FindFirst(JwtClaimTypes.Subject).Value, sub => new List<string>());
        }

        [HttpPut, Route, ClaimsAuthorize(new[] { "api_cv_profile:write" })]
        public string Set(ICollection<string> languages)
        {
            var cp = (ClaimsPrincipal) User;

            Database[cp.FindFirst(JwtClaimTypes.Subject).Value] = languages.ToList();

            return "OK, zmienione";
        }
    }
}
