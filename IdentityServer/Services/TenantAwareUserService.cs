using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IdentityServer3.Core;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using NLog;

namespace IdentityServer.Services
{
    public static class Tenants
    {
        public const string Pracuj = "pracuj";
        public const string Strefa = "strefa";
    }

    public class TenantAwareUserService : IUserService
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private static readonly Regex ServiceRegex = new Regex(@"^([a-z]+):(\d+)$");

        private readonly string _defaultServiceName;
        private readonly IReadOnlyDictionary<string, IUserService> _services;

        public TenantAwareUserService(IReadOnlyDictionary<string, IUserService> services, string defaultServiceName)
        {
            if (!services.ContainsKey(defaultServiceName))
                throw new ArgumentException($"Unknown default service '{defaultServiceName}'.");

            _services = services;
            _defaultServiceName = defaultServiceName;
        }

        public async Task PreAuthenticateAsync(PreAuthenticationContext context)
        {
            var serviceName = GetServiceName(context.SignInMessage);
            await _services[serviceName].PreAuthenticateAsync(context).ConfigureAwait(false);

            // context.AuthenticateResult = WrapAuthenticateResult(context.AuthenticateResult, serviceName);
        }

        public async Task AuthenticateLocalAsync(LocalAuthenticationContext context)
        {
            var serviceName = GetServiceName(context.SignInMessage);
            await _services[serviceName].AuthenticateLocalAsync(context).ConfigureAwait(false);

            // context.AuthenticateResult = WrapAuthenticateResult(context.AuthenticateResult, serviceName);
        }

        public async Task AuthenticateExternalAsync(ExternalAuthenticationContext context)
        {
            var serviceName = GetServiceName(context.SignInMessage);
            await _services[serviceName].AuthenticateExternalAsync(context).ConfigureAwait(false);

            context.AuthenticateResult = WrapAuthenticateResult(context.AuthenticateResult, serviceName);
        }

        public async Task PostAuthenticateAsync(PostAuthenticationContext context)
        {
            var serviceName = GetServiceName(context.SignInMessage);
            await _services[serviceName].PostAuthenticateAsync(context).ConfigureAwait(false);

            // context.AuthenticateResult = WrapAuthenticateResult(context.AuthenticateResult, serviceName);
        }

        public Task SignOutAsync(SignOutContext context)
        {
            var subject = context.Subject;
            var serviceName = GetServiceName(subject);
//            context.Subject = RemoveDuplicatedNameClaim(subject);

            return _services[serviceName].SignOutAsync(context);
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subject = context.Subject;
            var serviceName = GetServiceName(subject);
//            context.Subject = RemoveDuplicatedNameClaim(subject);

            return _services[serviceName].GetProfileDataAsync(context);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var subject = context.Subject;
            var serviceName = GetServiceName(subject);
//            context.Subject = RemoveDuplicatedNameClaim(subject);

            return _services[serviceName].IsActiveAsync(context);
        }

        private static ClaimsPrincipal RemoveDuplicatedNameClaim(ClaimsPrincipal subject)
        {
            var filtered = subject.Claims
                .Where(claim => claim.Type != Constants.ClaimTypes.Name);

            var claims = new List<Claim>(filtered);

            var identity = new ClaimsIdentity(claims);
            return new ClaimsPrincipal(identity);
        }

        private string GetServiceName(SignInMessage message)
        {
            if (string.IsNullOrEmpty(message.Tenant))
            {
                Logger.Debug("Missing tenant information, using default service.");
                return _defaultServiceName;
            }

            if (!_services.ContainsKey(message.Tenant))
            {
                Logger.Warn("Unknown service '{0}', using default service.", message.Tenant);
                return _defaultServiceName;
            }

            return message.Tenant;
        }

        private string GetServiceName(IPrincipal subject)
        {
            try
            {
                var id = subject.GetSubjectId();
                var serviceNameRegex = ServiceRegex.Match(id);

                if (!serviceNameRegex.Success)
                {
                    Logger.Warn("Subject ID ('{0}') does not match regular expression, using default service.", id);
                    return _defaultServiceName;
                }

                var candidate = serviceNameRegex.Groups[1].Value;

                if (_services.ContainsKey(candidate))
                {
                    Logger.Info("Using service '{0}', detected from subject ID.", candidate);
                    return candidate;
                }

                Logger.Warn("Unknown service '{0}', using default service.", candidate);
                return _defaultServiceName;
            }
            catch (InvalidOperationException)
            {
                Logger.Debug("Missing 'sub' claim, using default service.");
                return _defaultServiceName;
            }
        }

        private static AuthenticateResult WrapAuthenticateResult(AuthenticateResult authResult, string serviceName)
        {
            if (authResult == null || authResult.IsError || authResult.User == null)
                return authResult;

            //the code inserting a serviceName prefix to Subject claim should not do it twice when WrapAuthenticateResult called more than one.
            //first check if Subject claim already has a prefix
            var sub = authResult.User.Claims.First(c => c.Type == Constants.ClaimTypes.Subject);
            string id = sub.Value;

            //check if serviceName prefix set already on Subject claim
            if (id.Contains(":"))
            {
                string servicePrefix = id.Substring(0, id.LastIndexOf(":", StringComparison.Ordinal));
                if (servicePrefix != serviceName)
                {
                    throw new ArgumentException(
                        $"Service name already set in sub claim as: '{servicePrefix}' while attemting to set other service name of: '{serviceName}'.");
                }

                return authResult;
            }

            id = serviceName + ":" + id;

            var claims = (
                from claim in authResult.User.Claims
                let value = claim.Type == Constants.ClaimTypes.Subject ? id : claim.Value
                select new Claim(claim.Type, value, claim.ValueType)
            ).ToList();

            return new AuthenticateResult(id, authResult.User.GetName(), claims, authResult.User.GetIdentityProvider(), authResult.User.GetAuthenticationMethod());
        }
    }
}