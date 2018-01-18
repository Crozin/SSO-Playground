using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;

namespace PublicApiCvProfile.Controllers
{
    public class DummyController : ApiController
    {
        [HttpGet, Route("public")]
        public string HandlePublic()
        {
            return "hello";
        }

        [HttpGet, Route("secured"), Authorize]
        public IEnumerable<string> HandleSecured()
        {
            return ((ClaimsPrincipal) User).Claims.Select(c => $"{c.Type} = {c.Value}");
        }
    }
}