using SnippInternalIdentity.AuthApi.Models;
using SnippInternalIdentity.Domain.Entities;
using SnippInternalIdentity.Domain.Enums;
using SnippInternalIdentity.Domain.Interfaces;
using SnippInternalIdentity.Domain.ValueObjects;

namespace SnippInternalIdentity.AuthApi.Services;

/// <summary>
/// Service for handling authentication validation logic
/// </summary>
public class AuthenticationService
{
    private readonly IUserRepository _userRepository;
    private readonly IPermissionRepository _permissionRepository;
    private readonly IPasswordHashingService _passwordHashingService;
    private readonly IAuditLogRepository _auditLogRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        IUserRepository userRepository,
        IPermissionRepository permissionRepository,
        IPasswordHashingService passwordHashingService,
        IAuditLogRepository auditLogRepository,
        IUnitOfWork unitOfWork,
        ILogger<AuthenticationService> logger)
    {
        _userRepository = userRepository;
        _permissionRepository = permissionRepository;
        _passwordHashingService = passwordHashingService;
        _auditLogRepository = auditLogRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    /// <summary>
    /// Validates user credentials and checks if user has permission to access the specified application
    /// </summary>
    /// <param name="username">Username to validate</param>
    /// <param name="password">Password to validate</param>
    /// <param name="appName">Application name to check access for</param>
    /// <param name="ipAddress">Client IP address for logging</param>
    /// <returns>Authentication validation response</returns>
    public async Task<AuthValidationResponse> ValidateUserAccessAsync(
        string username, 
        string password, 
        string appName, 
        string? ipAddress = null)
    {
        var startTime = DateTime.UtcNow;
        
        try
        {
            _logger.LogInformation("Authentication attempt for user {Username} accessing {AppName} from IP {IpAddress}", 
                username, appName, ipAddress ?? "unknown");

            // Input validation
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(appName))
            {
                await LogAuthenticationAttempt(username, appName, false, "Invalid input parameters", ipAddress);
                return AuthValidationResponse.Failure("Invalid request parameters");
            }

            // Get user by username
            User? user;
            try
            {
                user = await _userRepository.GetByUsernameAsync(new Username(username));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user {Username}", username);
                await LogAuthenticationAttempt(username, appName, false, "Database error during user lookup", ipAddress);
                return AuthValidationResponse.Failure("Authentication failed");
            }

            // Check if user exists and is active
            if (user == null)
            {
                await LogAuthenticationAttempt(username, appName, false, "User not found", ipAddress);
                // Use constant time delay to prevent user enumeration
                await Task.Delay(200);
                return AuthValidationResponse.Failure("Authentication failed");
            }

            if (!user.IsActive)
            {
                await LogAuthenticationAttempt(username, appName, false, "User account disabled", ipAddress);
                return AuthValidationResponse.Failure("Account is disabled");
            }

            // Verify password
            bool isPasswordValid;
            try
            {
                isPasswordValid = _passwordHashingService.VerifyPassword(user.PasswordHash, password);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying password for user {Username}", username);
                await LogAuthenticationAttempt(username, appName, false, "Error verifying password", ipAddress);
                return AuthValidationResponse.Failure("Authentication failed");
            }

            if (!isPasswordValid)
            {
                await LogAuthenticationAttempt(username, appName, false, "Invalid password", ipAddress);
                // Use constant time delay to prevent timing attacks
                await Task.Delay(200);
                return AuthValidationResponse.Failure("Authentication failed");
            }

            // Get user with role and permissions
            var userWithRole = await _userRepository.GetWithRoleAsync(user.Id);
            if (userWithRole?.Role == null)
            {
                await LogAuthenticationAttempt(username, appName, false, "User role not found", ipAddress);
                return AuthValidationResponse.Failure("User configuration error");
            }

            // Check if user has permission for the requested application
            var hasPermission = await CheckUserPermissionAsync(userWithRole, appName);
            if (!hasPermission)
            {
                await LogAuthenticationAttempt(username, appName, false, "User lacks required permission", ipAddress);
                return AuthValidationResponse.Failure("Access denied - insufficient permissions");
            }

            // Get all permissions for the user's role
            var userPermissions = await GetUserPermissionsAsync(userWithRole.Role.Id, userWithRole.Role.IsSuperAdministrator);

            // Record successful login
            try
            {
                user.RecordLogin();
                await _unitOfWork.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update last login time for user {Username}", username);
                // Don't fail the authentication for this
            }

            // Log successful authentication
            await LogAuthenticationAttempt(username, appName, true, "Authentication successful", ipAddress);

            var authTime = DateTime.UtcNow - startTime;
            _logger.LogInformation("Successfully authenticated user {Username} for {AppName} in {ElapsedMs}ms", 
                username, appName, authTime.TotalMilliseconds);

            return AuthValidationResponse.Success(userWithRole.Role.Name, userPermissions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during authentication for user {Username} accessing {AppName}", 
                username, appName);
            
            await LogAuthenticationAttempt(username, appName, false, "Unexpected system error", ipAddress);
            return AuthValidationResponse.Failure("An error occurred during authentication");
        }
    }

    /// <summary>
    /// Checks if the user's role has permission to access the specified application
    /// </summary>
    private async Task<bool> CheckUserPermissionAsync(User user, string appName)
    {
        try
        {
            // Super administrators have access to everything
            if (user.Role.IsSuperAdministrator)
            {
                return true;
            }

            // Check if the user's role has the specific permission for this app
            var permissions = await _permissionRepository.GetByRoleAsync(user.Role.Id);
            return permissions.Any(p => p.Name.Equals(appName, StringComparison.OrdinalIgnoreCase) && p.IsActive);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking permissions for user {UserId} and app {AppName}", 
                user.Id, appName);
            return false;
        }
    }

    /// <summary>
    /// Gets all permission names for the user's role
    /// </summary>
    private async Task<List<string>> GetUserPermissionsAsync(int roleId, bool isSuperAdministrator)
    {
        try
        {
            if (isSuperAdministrator)
            {
                // Super administrators get all active permissions
                var allPermissions = await _permissionRepository.GetActivePermissionsAsync();
                return allPermissions.Select(p => p.Name).OrderBy(name => name).ToList();
            }
            else
            {
                // Regular users get permissions assigned to their role
                var rolePermissions = await _permissionRepository.GetByRoleAsync(roleId);
                return rolePermissions
                    .Where(p => p.IsActive)
                    .Select(p => p.Name)
                    .OrderBy(name => name)
                    .ToList();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting permissions for role {RoleId}", roleId);
            return new List<string>();
        }
    }

    /// <summary>
    /// Logs authentication attempt to audit log
    /// </summary>
    private async Task LogAuthenticationAttempt(
        string username, 
        string appName, 
        bool success, 
        string details, 
        string? ipAddress)
    {
        try
        {
            var auditLog = new AuditLog(
                entityType: "Users",
                action: success ? AuditAction.Login : AuditAction.AccessDenied, // Use AccessDenied for failed logins
                recordId: 0, // We don't have user ID for failed attempts, use 0
                oldValues: null,
                newValues: $"API authentication attempt for app '{appName}': {details}",
                ipAddress: ipAddress,
                userAgent: null, // We don't have user agent in this API
                changeReason: $"Authentication attempt for {appName}"
            );

            await _auditLogRepository.AddAsync(auditLog);
            await _unitOfWork.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log authentication attempt for user {Username}", username);
            // Don't throw - logging failure shouldn't break authentication
        }
    }
}