using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using IdentityModel.Client;

namespace PublicApiCvProfile.Controllers
{
    [RoutePrefix("photo")]
    public class PhotoController : ApiController
    {
        private static readonly ConcurrentDictionary<string, Guid> Database = new ConcurrentDictionary<string, Guid>();

        [HttpGet, Route, ClaimsAuthorize(new[] { "api_cv_profile:read" })]
        public async Task<HttpResponseMessage> Display()
        {
            string at;
            var cp = (ClaimsPrincipal) User;

            if (!Database.TryGetValue(cp.FindFirst("sub").Value, out Guid imageToken))
            {
                return Request.CreateResponse(HttpStatusCode.NotFound);
            }

            // wykorzystanie IdentityModel.Client w wersji 2.x jest nieco wygodniejsze (obsługuje .well-known/openid-configuration)

            using (var ct = new TokenClient("http://auth.sso.com/connect/token", "api_cv_profile", "secret"))
            {
                var res = await ct.RequestCustomGrantAsync("delegation", "api_filestore", new { token = cp.FindFirst("token").Value });

                if (string.IsNullOrEmpty(res.AccessToken))
                {
                    throw new Exception("ops... something went wrong");
                }

                at = res.AccessToken;
            }

            using (var client = new HttpClient { BaseAddress = new Uri("http://internal-api-filestore.sso/storage/"), DefaultRequestHeaders = { Authorization = new AuthenticationHeaderValue("Bearer", at)}})
            {
                var resp = await client.GetAsync(imageToken.ToString());

                if (!resp.IsSuccessStatusCode)
                    throw new Exception("coś poszło nie tak");

                var mt = resp.Content.Headers.ContentType.MediaType;
                var data = await resp.Content.ReadAsByteArrayAsync();
                
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(data) { Headers = { ContentType = new MediaTypeHeaderValue(mt) }}
                };
            }
        }

        [HttpPost, Route, ClaimsAuthorize(new[] { "api_cv_profile:write" })]
        public async Task<string> Update()
        {
            string at;
            var cp = (ClaimsPrincipal) User;

            // wykorzystanie IdentityModel.Client w wersji 2.x jest nieco wygodniejsze (obsługuje .well-known/openid-configuration)

            using (var ct = new TokenClient("http://auth.sso.com/connect/token", "api_cv_profile", "secret"))
            {
                var res = await ct.RequestCustomGrantAsync("delegation", "api_filestore", new { token = cp.FindFirst("token").Value });

                if (string.IsNullOrEmpty(res.AccessToken))
                {
                    throw new Exception("ops... something went wrong");
                }

                at = res.AccessToken;
            }


            using (var client = new HttpClient { BaseAddress = new Uri("http://internal-api-filestore.sso/storage/"), DefaultRequestHeaders = { Authorization = new AuthenticationHeaderValue("Bearer", at)}})
            {
                var mt = Request.Content.Headers.ContentType.MediaType;
                var data = await Request.Content.ReadAsByteArrayAsync();
                var resp = await client.PostAsync(string.Empty, new ByteArrayContent(data) { Headers = { ContentType = new MediaTypeHeaderValue(mt) } });

                if (!resp.IsSuccessStatusCode)
                    throw new Exception("coś poszło nie tak");

                var imageToken = await resp.Content.ReadAsAsync<Guid>();

                Database[cp.FindFirst("sub").Value] = imageToken;
            }

            return "OK";
        }
    }
}
