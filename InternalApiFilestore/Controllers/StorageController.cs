using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using IdentityModel;

namespace InternalApiFilestore.Controllers
{
    [RoutePrefix("storage")]
    public class StorageController : ApiController
    {
        private class DataEntry
        {
            private string Owner { get; }
            public string MediaType { get; }
            public byte[] Data { get; }

            public DataEntry(string owner, string mediaType, byte[] data)
            {
                Owner = owner;
                MediaType = mediaType;
                Data = data;
            }

            public bool CanAccess(ClaimsPrincipal ce)
            {
                return Owner == null || ce.FindAll(JwtClaimTypes.Subject).Any(c => c.Value == Owner);
            }
        }

        private static readonly ConcurrentDictionary<Guid, DataEntry> Database = new ConcurrentDictionary<Guid, DataEntry>();

        [HttpGet, Route("{token:guid}"), ClaimsAuthorize(new[] { "api_filestore:read" })]
        public HttpResponseMessage UnrestrictedRead(Guid token)
        {
            if (!Database.TryGetValue(token, out DataEntry de))
            {
                return Request.CreateErrorResponse(HttpStatusCode.NotFound, "ni ma...");
            }

            var ce = (ClaimsPrincipal) User;
            var ur = ce.FindFirst("api_filestore:unrestricted_read");

            if (ur == null && !de.CanAccess(ce))
            {
                return Request.CreateErrorResponse(HttpStatusCode.Forbidden, "aaaaa, nie wolno...");
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(de.Data)
                {
                    Headers =
                    {
                        ContentType = new MediaTypeHeaderValue(de.MediaType)
                    }
                }
            };
        }

        [HttpPost, Route, ClaimsAuthorize(new[] { "api_filestore:store" })]
        public async Task<Guid> Store()
        {
            var ce = (ClaimsPrincipal) User;
            var mt = Request.Content.Headers.ContentType.MediaType;
            var data = await Request.Content.ReadAsByteArrayAsync().ConfigureAwait(true);
            var token = Guid.NewGuid();

            Database[token] = new DataEntry(ce.FindFirst(JwtClaimTypes.Subject)?.Value, mt, data);

            return token;
        }
    }
}