namespace SnippInternalIdentity.AuthApi.Models;

/// <summary>
/// Response model for authentication validation
/// </summary>
public class AuthValidationResponse
{
    /// <summary>
    /// Whether the user has access to the requested application
    /// </summary>
    public bool HasAccess { get; set; }

    /// <summary>
    /// Descriptive message about the authentication result
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Name of the user's role (only returned on successful authentication)
    /// </summary>
    public string? RoleName { get; set; }

    /// <summary>
    /// Array of permission names associated with the user's role (only returned on successful authentication)
    /// </summary>
    public List<string>? Permissions { get; set; }

    /// <summary>
    /// Timestamp when the validation occurred
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Creates a successful authentication response
    /// </summary>
    public static AuthValidationResponse Success(string roleName, List<string> permissions)
    {
        return new AuthValidationResponse
        {
            HasAccess = true,
            Message = "User authenticated successfully",
            RoleName = roleName,
            Permissions = permissions,
            Timestamp = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Creates a failed authentication response
    /// </summary>
    public static AuthValidationResponse Failure(string message = "Authentication failed")
    {
        return new AuthValidationResponse
        {
            HasAccess = false,
            Message = message,
            Timestamp = DateTime.UtcNow
        };
    }
}