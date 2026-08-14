namespace CK.IO.User.UserPassword.Reset;

/// <summary>
/// Extends <see cref="Actor.IUserProfile"/> with the temporary password state.
/// </summary>
public interface IUserProfile : Actor.IUserProfile
{
    /// <summary>
    /// Gets or sets whether the current password is a temporary one: the user must
    /// choose a new password before being allowed to use the application.
    /// <para>
    /// This is false for users that have no password registration at all.
    /// </para>
    /// </summary>
    public bool IsTemporaryPassword { get; set; }
}
