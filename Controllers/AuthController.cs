using Microsoft.AspNetCore.Mvc;
using SnippInternalIdentity.AuthApi.Extensions;
using SnippInternalIdentity.AuthApi.Models;
using SnippInternalIdentity.AuthApi.Services;
using System.ComponentModel.DataAnnotations;

namespace SnippInternalIdentity.AuthApi.Controllers;

/// <summary>
/// Authentication validation controller for centralized user authentication
/// </summary>
[Route("api/[controller]")]
[ApiController]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly AuthenticationService _authenticationService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        AuthenticationService authenticationService,
        ILogger<AuthController> logger)
    {
        _authenticationService = authenticationService;
        _logger = logger;
    }

    /// <summary>
    /// Validates user credentials and checks if user has permission to access the specified application
    /// </summary>
    /// <param name="request">Authentication validation request containing appName</param>
    /// <returns>Authentication validation response indicating whether user has access</returns>
    /// <remarks>
    /// This endpoint accepts credentials via Basic Authentication header:
    /// 
    /// **Basic Authentication Header:**
    /// 
    ///     POST /api/auth/validate
    ///     Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
    ///     Content-Type: application/json
    ///     
    ///     {
    ///       "appName": "Internal Identity Authentication"
    ///     }
    /// 
    /// **Success Response:**
    /// 
    ///     {
    ///       "hasAccess": true,
    ///       "message": "User authenticated successfully",
    ///       "roleName": "Administrator",
    ///       "permissions": [
    ///         "Internal Identity Authentication",
    ///         "Snipp Tiny Url",
    ///         "P&amp;G CMS Rebate Center"
    ///       ],
    ///       "firstName": "Sunil",
    ///       "lastName": "Kumar",
    ///       "email": "sunil.kumar@snippinteractive.com",
    ///       "phoneNumber": "+1-555-0123",
    ///       "timestamp": "2025-09-03T10:30:00Z"
    ///     }
    /// 
    /// **Failure Response (401 Unauthorized):**
    /// 
    ///     {
    ///       "hasAccess": false,
    ///       "message": "Authentication failed",
    ///       "reason": "InvalidCredentials",
    ///       "timestamp": "2025-09-03T10:30:00Z"
    ///     }
    /// 
    /// **Failure Response (403 Forbidden):**
    /// 
    ///     {
    ///       "hasAccess": false,
    ///       "message": "Access denied - insufficient permissions",
    ///       "reason": "InsufficientPermissions",
    ///       "timestamp": "2025-09-03T10:30:00Z"
    ///     }
    /// </remarks>
    /// <response code="200">User authenticated successfully</response>
    /// <response code="400">Invalid request parameters</response>
    /// <response code="401">Invalid credentials or account disabled</response>
    /// <response code="403">User lacks permission for the requested application</response>
    /// <response code="429">Too many requests - rate limit exceeded</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("validate")]
    [ProducesResponseType(typeof(AuthValidationResponse), 200)]
    [ProducesResponseType(typeof(AuthValidationResponse), 400)]
    [ProducesResponseType(typeof(AuthValidationResponse), 401)]
    [ProducesResponseType(typeof(AuthValidationResponse), 403)]
    [ProducesResponseType(429)]
    [ProducesResponseType(typeof(AuthValidationResponse), 500)]
    public async Task<ActionResult<AuthValidationResponse>> Validate(
        [FromBody, Required] AuthValidationRequest request)
    {
        try
        {
            // Get client IP address for logging
            var clientIp = GetClientIpAddress();
            
            _logger.LogInformation("Received authentication validation request for app {AppName} from IP {ClientIp}", 
                request.AppName, clientIp);

            // Extract credentials from Basic Auth header
            var credentials = GetCredentials(request);
            if (credentials == null)
            {
                _logger.LogWarning("No valid credentials provided in request for app {AppName} from IP {ClientIp}", 
                    request.AppName, clientIp);
                var errorResponse = AuthValidationResponse.Failure("No valid credentials provided", AuthValidationResponse.FailureReason.InvalidInput);
                return BadRequest(errorResponse);
            }

            var (username, password) = credentials.Value;

            // Validate credentials and check permissions
            var result = await _authenticationService.ValidateUserAccessAsync(
                username, password, request.AppName, clientIp);

            // Log the result (but not sensitive details)
            if (result.HasAccess)
            {
                _logger.LogInformation("Authentication successful for user {Username} accessing {AppName} from IP {ClientIp}", 
                    username, request.AppName, clientIp);
                return Ok(result);
            }
            else
            {
                _logger.LogWarning("Authentication failed for user {Username} accessing {AppName} from IP {ClientIp}: {Message}", 
                    username, request.AppName, clientIp, result.Message);
                
                // Return appropriate HTTP status code based on failure reason
                return result.Reason switch
                {
                    AuthValidationResponse.FailureReason.InvalidInput => BadRequest(result),
                    AuthValidationResponse.FailureReason.InvalidCredentials => Unauthorized(result),
                    AuthValidationResponse.FailureReason.AccountDisabled => Unauthorized(result),
                    AuthValidationResponse.FailureReason.InsufficientPermissions => StatusCode(403, result), // Forbidden
                    AuthValidationResponse.FailureReason.SystemError => StatusCode(500, result), // Internal Server Error
                    _ => Unauthorized(result) // Default to Unauthorized for unknown reasons
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error processing authentication validation for app {AppName}", request.AppName);
            var errorResponse = AuthValidationResponse.Failure("An error occurred during authentication", AuthValidationResponse.FailureReason.SystemError);
            return StatusCode(500, errorResponse);
        }
    }

    /// <summary>
    /// Health check endpoint to verify API is running
    /// </summary>
    /// <returns>Simple health status</returns>
    /// <response code="200">API is healthy</response>
    [HttpGet("health")]
    [ProducesResponseType(200)]
    public IActionResult Health()
    {
        return Ok(new { status = "healthy", timestamp = DateTime.UtcNow });
    }

    /// <summary>
    /// Extracts credentials from Basic Auth header
    /// </summary>
    /// <param name="request">The validation request</param>
    /// <returns>Username and password tuple, or null if not found</returns>
    private (string Username, string Password)? GetCredentials(AuthValidationRequest request)
    {
        // Get credentials from Basic Auth header only
        var basicAuthCredentials = Request.GetBasicAuthCredentials();
        if (basicAuthCredentials.HasValue)
        {
            return basicAuthCredentials.Value;
        }

        // No credentials found
        return null;
    }

    /// <summary>
    /// Gets the client IP address from the request
    /// </summary>
    /// <returns>Client IP address or "unknown" if not available</returns>
    private string GetClientIpAddress()
    {
        try
        {
            // Check for IP in X-Forwarded-For header (for load balancers/proxies)
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                var forwardedIps = Request.Headers["X-Forwarded-For"].ToString();
                if (!string.IsNullOrEmpty(forwardedIps))
                {
                    // Take the first IP from the comma-separated list
                    return forwardedIps.Split(',')[0].Trim();
                }
            }

            // Check for IP in X-Real-IP header
            if (Request.Headers.ContainsKey("X-Real-IP"))
            {
                var realIp = Request.Headers["X-Real-IP"].ToString();
                if (!string.IsNullOrEmpty(realIp))
                {
                    return realIp.Trim();
                }
            }

            // Fall back to remote IP address
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }
}