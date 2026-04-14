using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPassword;

/// <summary>
/// Changes the password of an existing password user.
/// The actor must be the target user itself (ActorId must match UserId).
/// Maps to <c>UserPasswordTable.SetPasswordAsync</c> which operates in <c>UCLMode.UpdateOnly</c>.
/// </summary>
public interface ISetPasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthNormal
{
    /// <summary>
    /// Gets or sets the target user identifier. Must match the authenticated <c>ActorId</c>.
    /// </summary>
    public int UserId { get; set; }

    /// <summary>
    /// Gets or sets the new password to set.
    /// </summary>
    public string Password { get; set; }
}
