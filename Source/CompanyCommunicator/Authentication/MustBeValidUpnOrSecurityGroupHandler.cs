// <copyright file="MustBeValidUpnHandler.cs" company="Microsoft">
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// </copyright>

namespace Microsoft.Teams.Apps.CompanyCommunicator.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Options;
    using Microsoft.Graph;

    /// <summary>
    /// This class is an authorization handler, which handles the authorization requirement.
    /// </summary>
    public class MustBeValidUpnOrSecurityGroupHandler : AuthorizationHandler<MustBeValidUpnOrSecurityGroupRequirement>
    {
        private readonly bool disableCreatorUpnCheck;
        private readonly IInnerHandler innerHandler;

        /// <summary>
        /// Initializes a new instance of the <see cref="MustBeValidUpnOrSecurityGroupHandler"/> class.
        /// </summary>
        /// <param name="authenticationOptions">The authentication options.</param>
        /// <param name="logger">logger.</param>
        /// <param name="graphServiceClient">graph service client.</param>
        /// <param name="cache">The cache.</param>
        public MustBeValidUpnOrSecurityGroupHandler(
            IOptions<AuthenticationOptions> authenticationOptions,
            IGraphServiceClient graphServiceClient,
            IMemoryCache cache)
        {
            this.disableCreatorUpnCheck = authenticationOptions.Value.DisableCreatorUpnCheck;
            var authorizedCreatorUpns = authenticationOptions.Value.AuthorizedCreatorUpns;
            this.innerHandler = Guid.TryParse(authorizedCreatorUpns, out var _) ?
                (IInnerHandler)new MemberOfSecurityGroupInnerHandler(authorizedCreatorUpns, cache, graphServiceClient) :
                new MemberOfAuthorizedCreatorUpnsInnerHandler(authorizedCreatorUpns);
        }

        /// <summary>
        /// Inner handler for HandleRequirementAsync
        /// </summary>
        private interface IInnerHandler
        {
            /// <summary>
            /// Inner handler.
            /// </summary>
            /// <param name="upn">The upn.</param>
            /// <returns>valid or invalid</returns>
            Task<bool> HandleRequirementAsync(string upn);
        }

        /// <summary>
        /// This method handles the authorization requirement.
        /// </summary>
        /// <param name="context">AuthorizationHandlerContext instance.</param>
        /// <param name="requirement">IAuthorizationRequirement instance.</param>
        /// <returns>A task that represents the work queued to execute.</returns>
        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            MustBeValidUpnOrSecurityGroupRequirement requirement)
        {
            if (this.disableCreatorUpnCheck) { return; }

            var upn = GetUpnOrEmailFromContext(context);
            if (string.IsNullOrWhiteSpace(upn))
            {
                return;
            }

            if (await this.innerHandler.HandleRequirementAsync(upn))
            {
                context.Succeed(requirement);
            }
        }

        private static string GetUpnOrEmailFromContext(AuthorizationHandlerContext context)
        {
            var claimupn = context.User?.Claims?.FirstOrDefault(p => p.Type == ClaimTypes.Upn);
            var upn = claimupn?.Value;

            var claimemail = context.User?.Claims?.FirstOrDefault(p => p.Type == ClaimTypes.Email);
            var email = claimemail?.Value;
            return upn ?? email;
        }

        private class MemberOfAuthorizedCreatorUpnsInnerHandler : IInnerHandler
        {
            private readonly HashSet<string> authorizedCreatorUpnsSet;

            public MemberOfAuthorizedCreatorUpnsInnerHandler(string authorizedCreatorUpns)
            {
                this.authorizedCreatorUpnsSet = authorizedCreatorUpns
                    ?.Split(new char[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
                    ?.Select(p => p.Trim())
                    ?.ToHashSet()
                    ?? new HashSet<string>();
            }

            public Task<bool> HandleRequirementAsync(string upn) => Task.FromResult(this.authorizedCreatorUpnsSet.Contains(upn, StringComparer.OrdinalIgnoreCase));
        }

        private class MemberOfSecurityGroupInnerHandler : IInnerHandler
        {
            private readonly string[] securityGroupIds;
            private readonly IMemoryCache memoryCache;
            private readonly IGraphServiceClient graphServiceClient;

            public MemberOfSecurityGroupInnerHandler(string securityGroupId, IMemoryCache memoryCache, IGraphServiceClient graphServiceClient)
            {
                this.securityGroupIds = new[] { securityGroupId };
                this.memoryCache = memoryCache;
                this.graphServiceClient = graphServiceClient;
            }

            public async Task<bool> HandleRequirementAsync(string upn) =>
                await this.memoryCache.GetOrCreateAsync(upn, async entry =>
                {
                    entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15);
                    var memberGroups = await this.graphServiceClient.Me.CheckMemberGroups(this.securityGroupIds).Request().PostAsync();
                    return memberGroups.Any();
                });
        }
    }
}
