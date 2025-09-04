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
    /// <param name="request">Authentication validation request containing appName and optionally username/password</param>
    /// <returns>Authentication validation response indicating whether user has access</returns>
    /// <remarks>
    /// This endpoint accepts credentials in two ways:
    /// 
    /// **Method 1: Basic Authentication Header (for Web Applications)**
    /// 
    ///     POST /api/auth/validate
    ///     Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
    ///     Content-Type: application/json
    ///     
    ///     {
    ///       "appName": "Internal Identity Authentication"
    ///     }
    /// 
    /// **Method 2: Credentials in Request Body (for API Applications)**
    /// 
    ///     POST /api/auth/validate
    ///     Content-Type: application/json
    ///     
    ///     {
    ///       "appName": "Snipp Tiny Url",
    ///       "username": "sunil.kumar",
    ///       "password": "Admin@123"
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
    ///       "timestamp": "2025-09-03T10:30:00Z"
    ///     }
    /// 
    /// **Failure Response:**
    /// 
    ///     {
    ///       "hasAccess": false,
    ///       "message": "Authentication failed",
    ///       "timestamp": "2025-09-03T10:30:00Z"
    ///     }
    /// </remarks>
    /// <response code="200">Authentication validation completed (check hasAccess field for result)</response>
    /// <response code="400">Invalid request parameters</response>
    /// <response code="429">Too many requests - rate limit exceeded</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("validate")]
    [ProducesResponseType(typeof(AuthValidationResponse), 200)]
    [ProducesResponseType(typeof(ValidationProblemDetails), 400)]
    [ProducesResponseType(429)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<AuthValidationResponse>> Validate(
        [FromBody, Required] AuthValidationRequest request)
    {
        try
        {
            // Get client IP address for logging
            var clientIp = GetClientIpAddress();
            
            _logger.LogInformation("Received authentication validation request for app {AppName} from IP {ClientIp}", 
                request.AppName, clientIp);

            // Extract credentials from either Basic Auth header or request body
            var credentials = GetCredentials(request);
            if (credentials == null)
            {
                _logger.LogWarning("No valid credentials provided in request for app {AppName} from IP {ClientIp}", 
                    request.AppName, clientIp);
                return Ok(AuthValidationResponse.Failure("No valid credentials provided"));
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
            }
            else
            {
                _logger.LogWarning("Authentication failed for user {Username} accessing {AppName} from IP {ClientIp}: {Message}", 
                    username, request.AppName, clientIp, result.Message);
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error processing authentication validation for app {AppName}", request.AppName);
            return Ok(AuthValidationResponse.Failure("An error occurred during authentication"));
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
    /// Extracts credentials from either Basic Auth header or request body
    /// </summary>
    /// <param name="request">The validation request</param>
    /// <returns>Username and password tuple, or null if not found</returns>
    private (string Username, string Password)? GetCredentials(AuthValidationRequest request)
    {
        // First, try to get credentials from Basic Auth header
        var basicAuthCredentials = Request.GetBasicAuthCredentials();
        if (basicAuthCredentials.HasValue)
        {
            return basicAuthCredentials.Value;
        }

        // If no Basic Auth, try to get from request body
        if (!string.IsNullOrWhiteSpace(request.Username) && !string.IsNullOrWhiteSpace(request.Password))
        {
            return (request.Username, request.Password);
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