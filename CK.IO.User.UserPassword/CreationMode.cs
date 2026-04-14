namespace CK.IO.User.UserPassword;

/// <summary>
/// Defines the creation or update behavior for a user password registration.
/// This is the IO-layer equivalent of <c>UCLMode</c> (Create/Update part only, without the login flags).
/// </summary>
public enum CreationMode
{
    /// <summary>
    /// Creates or updates the user password registration. This is the default mode.
    /// </summary>
    CreateOrUpdate = 0,

    /// <summary>
    /// Only a new user password registration must be created.
    /// Fails if the registration already exists.
    /// </summary>
    CreateOnly = 1,

    /// <summary>
    /// Only an existing user password registration must be updated.
    /// Fails if the registration does not exist.
    /// </summary>
    UpdateOnly = 2
}
