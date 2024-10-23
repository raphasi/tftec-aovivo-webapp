using CRM.Application.DTOs;
using CRM.Application.Interfaces;
using CRM.Infrastructure.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace CRM.API.AUTH.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ITokenService tokenService,
                              UserManager<ApplicationUser> userManager,
                              RoleManager<IdentityRole> roleManager,
                              IConfiguration configuration,
                              ILogger<AuthController> logger)
        {
            _tokenService = tokenService;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _logger = logger;
        }

        [Authorize(Policy = "AdminOnly")]
        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Role name cannot be empty." });
            }

            if (await _roleManager.RoleExistsAsync(roleName))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Role already exists." });
            }

            var roleResult = await _roleManager.CreateAsync(new IdentityRole(roleName));
            if (roleResult.Succeeded)
            {
                _logger.LogInformation("Role {RoleName} added successfully", roleName);
                return Ok(new ResponseDTO { Status = "Success", Message = $"Role {roleName} added successfully" });
            }

            _logger.LogError("Error adding role {RoleName}", roleName);
            return BadRequest(new ResponseDTO { Status = "Error", Message = $"Issue adding the new {roleName} role" });
        }

        [HttpPost("AddUserToRole")]
        private async Task<IActionResult> AddUserToRole(string email, string roleName)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(roleName))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Email and role name cannot be empty." });
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound(new ResponseDTO { Status = "Error", Message = "User not found." });
            }

            var result = await _userManager.AddToRoleAsync(user, roleName);
            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} added to the {RoleName} role", email, roleName);
                return Ok(new ResponseDTO { Status = "Success", Message = $"User {email} added to the {roleName} role" });
            }

            _logger.LogError("Error adding user {Email} to the {RoleName} role", email, roleName);
            return BadRequest(new ResponseDTO { Status = "Error", Message = $"Error adding user {email} to the {roleName} role" });
        }

        [HttpPost("SyncAzureAdUser")]
        public async Task<IActionResult> SyncAzureAdUser([FromHeader(Name = "Authorization")] string authorization)
        {
            if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Access token is missing or invalid." });
            }

            var accessToken = authorization.Substring("Bearer ".Length).Trim();

            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtSecurityToken;

            try
            {
                jwtSecurityToken = handler.ReadJwtToken(accessToken);
            }
            catch (Exception)
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Invalid token format." });
            }

            var email = jwtSecurityToken.Claims.FirstOrDefault(claim => claim.Type == "upn" || claim.Type == "email")?.Value;
            var fullName = jwtSecurityToken.Claims.FirstOrDefault(claim => claim.Type == "upn" || claim.Type == "name")?.Value;
            var objectId = jwtSecurityToken.Claims.FirstOrDefault(claim => claim.Type == "oid")?.Value;

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(objectId))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Invalid token: missing required claims." });
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    FullName = fullName,
                    Email = email,
                    SecurityIdentifierString = objectId
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to create user {Email}", email);
                    return StatusCode(500, new ResponseDTO { Status = "Error", Message = "Failed to create user." });
                }
                await AddUserToRole(user.Email, "Admin");
            }

            user.SecurityIdentifierString = objectId;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                _logger.LogError("Failed to update user {Email}", email);
                return StatusCode(500, new ResponseDTO { Status = "Error", Message = "Failed to update user information." });
            }

            

            var tokenResponse = await GenerateTokenResponse(user);
            return Ok(tokenResponse);
        }

        [HttpPost("SyncAzureB2cUser")]
        public async Task<IActionResult> SyncAzureB2cUser([FromHeader(Name = "Authorization")] string authorization)
        {
            if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Access token is missing or invalid." });
            }

            var accessToken = authorization.Substring("Bearer ".Length).Trim();

            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtSecurityToken;

            try
            {
                jwtSecurityToken = handler.ReadJwtToken(accessToken);
            }
            catch (Exception)
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Invalid token format." });
            }

            var email = jwtSecurityToken.Claims.FirstOrDefault(claim => claim.Type == "upn" || claim.Type == "emails")?.Value;
            var fullName = jwtSecurityToken.Claims.FirstOrDefault(claim => claim.Type == "upn" || claim.Type == "name")?.Value;
            var objectId = jwtSecurityToken.Claims.FirstOrDefault(claim => claim.Type == "oid")?.Value;

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(objectId))
            {
                return BadRequest(new ResponseDTO { Status = "Error", Message = "Invalid token: missing required claims." });
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    FullName = fullName,
                    Email = email,
                    SecurityIdentifierString = objectId
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to create user {Email}", email);
                    return StatusCode(500, new ResponseDTO { Status = "Error", Message = "Failed to create user." });
                }
                await AddUserToRole(user.Email, "Admin");
            }

            user.SecurityIdentifierString = objectId;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                _logger.LogError("Failed to update user {Email}", email);
                return StatusCode(500, new ResponseDTO { Status = "Error", Message = "Failed to update user information." });
            }



            var tokenResponse = await GenerateTokenResponse(user);
            return Ok(tokenResponse);
        }

        private async Task SyncUserRoles(ApplicationUser user, IEnumerable<Claim> azureAdClaims)
        {
            try
            {
                var currentRoles = await _userManager.GetRolesAsync(user);
                var newRoles = new HashSet<string>();

                // Log all claims for debugging
                _logger.LogInformation($"All claims for user {user.Email}:");
                foreach (var claim in azureAdClaims)
                {
                    _logger.LogInformation($"Type: {claim.Type}, Value: {claim.Value}");
                }

                // Check for roles in various possible claim types
                var roleClaims = azureAdClaims.Where(c =>
                    c.Type == "roles" ||
                    c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" ||
                    c.Type == "role" ||
                    c.Type == "groups" ||  // Azure AD can sometimes use groups to represent roles
                    c.Type.EndsWith("/role")
                );

                foreach (var claim in roleClaims)
                {
                    var roleName = MapAzureAdRoleToLocalRole(claim.Value);
                    if (!string.IsNullOrEmpty(roleName))
                    {
                        newRoles.Add(roleName);
                    }
                }

                // If no roles found, check if there's a single role claim
                if (!newRoles.Any())
                {
                    var singleRoleClaim = azureAdClaims.FirstOrDefault(c => c.Type.Contains("role", StringComparison.OrdinalIgnoreCase));
                    if (singleRoleClaim != null)
                    {
                        var roleName = MapAzureAdRoleToLocalRole(singleRoleClaim.Value);
                        if (!string.IsNullOrEmpty(roleName))
                        {
                            newRoles.Add(roleName);
                        }
                    }
                }

                _logger.LogInformation($"Current roles for user {user.Email}: {string.Join(", ", currentRoles)}");
                _logger.LogInformation($"New roles from Azure AD for user {user.Email}: {string.Join(", ", newRoles)}");

                var rolesToRemove = currentRoles.Except(newRoles).ToList();
                var rolesToAdd = newRoles.Except(currentRoles).ToList();

                if (rolesToRemove.Any())
                {
                    var removeResult = await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
                    if (!removeResult.Succeeded)
                    {
                        _logger.LogError($"Failed to remove roles for user {user.Email}: {string.Join(", ", removeResult.Errors.Select(e => e.Description))}");
                    }
                    else
                    {
                        _logger.LogInformation($"Removed roles for user {user.Email}: {string.Join(", ", rolesToRemove)}");
                    }
                }

                if (rolesToAdd.Any())
                {
                    var addResult = await _userManager.AddToRolesAsync(user, rolesToAdd);
                    if (!addResult.Succeeded)
                    {
                        _logger.LogError($"Failed to add roles for user {user.Email}: {string.Join(", ", addResult.Errors.Select(e => e.Description))}");
                    }
                    else
                    {
                        _logger.LogInformation($"Added roles for user {user.Email}: {string.Join(", ", rolesToAdd)}");
                    }
                }

                // Verify the roles after synchronization
                var updatedRoles = await _userManager.GetRolesAsync(user);
                _logger.LogInformation($"Updated roles for user {user.Email}: {string.Join(", ", updatedRoles)}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error synchronizing roles for user {user.Email}: {ex.Message}");
            }
        }

        private string MapAzureAdRoleToLocalRole(string azureAdRole)
        {
            // Implement your role mapping logic here
            // For now, we'll just return the Azure AD role as-is
            return azureAdRole;
        }

        private async Task<TokenDTO> GenerateTokenResponse(ApplicationUser user)
        {
            //var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            //foreach (var userRole in userRoles)
            //{
            //    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            //}

            var token = _tokenService.GenerateAccessToken(authClaims, _configuration);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);

            var userInfo = new UserInfoDTO
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                LeadID = user.LeadID,
                SecurityIdentifier = user.SecurityIdentifierString
                //Roles = userRoles.ToList()
            };

            return new TokenDTO
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                UserInfo = userInfo
            };
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenDTO tokenModel)
        {
            if (tokenModel == null)
            {
                return BadRequest("Invalid client request");
            }

            var principal = _tokenService.GetClaimsPrincipalFromExpiredToken(tokenModel.AccessToken, _configuration);
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);
            if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var newAccessToken = _tokenService.GenerateAccessToken(principal.Claims.ToList(), _configuration);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);

            return Ok(new TokenDTO
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                RefreshToken = newRefreshToken,
                UserInfo = new UserInfoDTO
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    LeadID = user.LeadID,
                    SecurityIdentifier = user.SecurityIdentifierString,
                    Roles = await _userManager.GetRolesAsync(user)
                }
            });
        }

        [Authorize]
        [HttpPost("Revoke")]
        public async Task<IActionResult> Revoke()
        {
            var username = User.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                return BadRequest("Invalid user name");
            }

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);

            return NoContent();
        }
    }
}