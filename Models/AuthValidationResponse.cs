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
    /// User's first name (only returned on successful authentication)
    /// </summary>
    public string? FirstName { get; set; }

    /// <summary>
    /// User's last name (only returned on successful authentication)
    /// </summary>
    public string? LastName { get; set; }

    /// <summary>
    /// User's email address (only returned on successful authentication)
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// User's phone number (only returned on successful authentication)
    /// </summary>
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Timestamp when the validation occurred
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Creates a successful authentication response
    /// </summary>
    public static AuthValidationResponse Success(string roleName, List<string> permissions, 
        string firstName, string lastName, string email, string? phoneNumber)
    {
        return new AuthValidationResponse
        {
            HasAccess = true,
            Message = "User authenticated successfully",
            RoleName = roleName,
            Permissions = permissions,
            FirstName = firstName,
            LastName = lastName,
            Email = email,
            PhoneNumber = phoneNumber,
            Timestamp = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Failure reason for authentication
    /// </summary>
    public enum FailureReason
    {
        InvalidCredentials,
        InsufficientPermissions,
        AccountDisabled,
        InvalidInput,
        SystemError
    }

    /// <summary>
    /// Reason for authentication failure (only set when HasAccess is false)
    /// </summary>
    public FailureReason? Reason { get; set; }

    /// <summary>
    /// Creates a failed authentication response
    /// </summary>
    public static AuthValidationResponse Failure(string message = "Authentication failed", FailureReason? reason = null)
    {
        return new AuthValidationResponse
        {
            HasAccess = false,
            Message = message,
            Reason = reason,
            Timestamp = DateTime.UtcNow
        };
    }
}