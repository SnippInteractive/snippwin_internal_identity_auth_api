using System.ComponentModel.DataAnnotations;

namespace SnippInternalIdentity.AuthApi.Models;

/// <summary>
/// Request model for authentication validation
/// </summary>
public class AuthValidationRequest
{
    /// <summary>
    /// Name of the application requesting access validation
    /// </summary>
    [Required(ErrorMessage = "Application name is required")]
    [StringLength(255, ErrorMessage = "Application name cannot exceed 255 characters")]
    public string AppName { get; set; } = string.Empty;
}