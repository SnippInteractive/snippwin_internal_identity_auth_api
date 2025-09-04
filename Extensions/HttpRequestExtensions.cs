using System.Text;

namespace SnippInternalIdentity.AuthApi.Extensions;

/// <summary>
/// Extension methods for HttpRequest
/// </summary>
public static class HttpRequestExtensions
{
    /// <summary>
    /// Extracts username and password from Basic Authentication header
    /// </summary>
    /// <param name="request">HTTP request</param>
    /// <returns>Tuple containing username and password, or null if not found or invalid</returns>
    public static (string Username, string Password)? GetBasicAuthCredentials(this HttpRequest request)
    {
        try
        {
            if (!request.Headers.ContainsKey("Authorization"))
                return null;

            var authHeader = request.Headers["Authorization"].ToString();
            
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                return null;

            // Extract the encoded credentials part
            var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
            
            if (string.IsNullOrEmpty(encodedCredentials))
                return null;

            // Decode the base64 string
            byte[] credentialsBytes;
            try
            {
                credentialsBytes = Convert.FromBase64String(encodedCredentials);
            }
            catch (FormatException)
            {
                // Invalid base64 encoding
                return null;
            }

            var credentials = Encoding.UTF8.GetString(credentialsBytes);
            var colonIndex = credentials.IndexOf(':');
            
            if (colonIndex <= 0 || colonIndex == credentials.Length - 1)
                return null;

            var username = credentials.Substring(0, colonIndex);
            var password = credentials.Substring(colonIndex + 1);

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return null;

            return (username, password);
        }
        catch
        {
            // Any unexpected error in parsing
            return null;
        }
    }
}