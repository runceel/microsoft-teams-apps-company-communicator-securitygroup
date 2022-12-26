// <copyright file="MustBeValidUpnHandler.cs" company="Microsoft">
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// </copyright>

namespace Microsoft.Teams.Apps.CompanyCommunicator.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.Graph;
    using Microsoft.Identity.Web;
    using Newtonsoft.Json;

    /// <summary>
    /// This class is an authorization handler, which handles the authorization requirement.
    /// </summary>
    public class MustBeValidUpnOrSecurityGroupHandler : AuthorizationHandler<MustBeValidUpnOrSecurityGroupRequirement>
    {
        private readonly bool disableCreatorUpnCheck;
        private string[] securityGroupIds;
        private readonly HashSet<string> authorizedCreatorUpnsSet;
        private readonly ILogger<MustBeValidUpnOrSecurityGroupHandler> logger;
        private readonly IGraphServiceClient graphServiceClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="MustBeValidUpnOrSecurityGroupHandler"/> class.
        /// </summary>
        /// <param name="authenticationOptions">The authentication options.</param>
        /// <param name="logger">logger.</param>
        /// <param name="graphServiceClient">graph service client.</param>
        public MustBeValidUpnOrSecurityGroupHandler(IOptions<AuthenticationOptions> authenticationOptions, 
            ILogger<MustBeValidUpnOrSecurityGroupHandler> logger,
            IGraphServiceClient graphServiceClient)
        {
            this.disableCreatorUpnCheck = authenticationOptions.Value.DisableCreatorUpnCheck;
            var authorizedCreatorUpns = authenticationOptions.Value.AuthorizedCreatorUpns;
            if (Guid.TryParse(authorizedCreatorUpns, out var _))
            {
                this.securityGroupIds = new[] { authorizedCreatorUpns };
            }
            else
            {
                this.authorizedCreatorUpnsSet = authorizedCreatorUpns
                    ?.Split(new char[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
                    ?.Select(p => p.Trim())
                    ?.ToHashSet()
                    ?? new HashSet<string>();
            }
            this.logger = logger;
            this.graphServiceClient = graphServiceClient;
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
            if (this.disableCreatorUpnCheck) return;

            if (this.authorizedCreatorUpnsSet != null && this.IsValidUpn(context))
            {
                context.Succeed(requirement);
            } 
            else if (this.securityGroupIds != null && await this.IsMemverOfSecurityGroupAsync())
            {
                context.Succeed(requirement);
            }
        }

        private async Task<bool> IsMemverOfSecurityGroupAsync()
        {
            var memberGroups = await this.graphServiceClient.Me.CheckMemberGroups(this.securityGroupIds).Request().PostAsync();
            return memberGroups.Any();
        }

        /// <summary>
        /// Check whether a upn (or alternate email for external authors) is valid or not.
        /// This is where we should check against the valid list of UPNs.
        /// </summary>
        /// <param name="context">Authorization handler context instance.</param>
        /// <returns>Indicate if a upn is valid or not.</returns>
        private bool IsValidUpn(AuthorizationHandlerContext context)
        {
            var claimupn = context.User?.Claims?.FirstOrDefault(p => p.Type == ClaimTypes.Upn);
            var upn = claimupn?.Value;

            var claimemail = context.User?.Claims?.FirstOrDefault(p => p.Type == ClaimTypes.Email);
            var email = claimemail?.Value;

            if (string.IsNullOrWhiteSpace(upn) && string.IsNullOrWhiteSpace(email))
            {
                return false;
            }

            bool upncheck = this.authorizedCreatorUpnsSet.Contains(upn, StringComparer.OrdinalIgnoreCase);
            bool emailcheck = this.authorizedCreatorUpnsSet.Contains(email, StringComparer.OrdinalIgnoreCase);

            if (upncheck || emailcheck)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
