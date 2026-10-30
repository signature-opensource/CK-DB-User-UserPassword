namespace CK.DB.User.UserPassword;

/// <summary>
/// The result of <see cref="UserPasswordTable.RemovePasswordAsync"/>.
/// </summary>
public enum PasswordRemoveResult
{
    /// <summary>
    /// The user has no password.
    /// </summary>
    NotFound = 0,

    /// <summary>
    /// The password has been removed.
    /// </summary>
    Removed = 1,

    /// <summary>
    /// Refused: the password is the user's last way to log in.
    /// </summary>
    LastLoginMethod = 2
}
