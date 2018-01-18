using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace InternalApiOffers
{
    public class ClaimsAuthorizeAttribute : AuthorizeAttribute
    {
        private readonly IEnumerable<string> requiredClaims;

        public ClaimsAuthorizeAttribute(string[] requiredClaims)
        {
            if (requiredClaims == null)
                throw new ArgumentNullException(nameof(requiredClaims));

            if (!requiredClaims.Any())
                throw new ArgumentException($"{nameof(requiredClaims)} cannot be empty");

            this.requiredClaims = requiredClaims;
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            if (!base.IsAuthorized(actionContext))
                return false;

            var identity = actionContext.ControllerContext.RequestContext.Principal.Identity as ClaimsIdentity;
            var claims = identity?.Claims.ToList();

            foreach (var requiredClaim in requiredClaims)
            {
                var claim = claims?.FirstOrDefault(c => c.Type == requiredClaim);

                if (claim == null)
                    return false;
            }

            return true;
        }
    }
}