using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPassword;

/// <summary>
/// Creates or updates a user password registration.
/// Maps to <c>UserPasswordTable.CreateOrUpdatePasswordUserAsync</c> with a <c>UCLMode</c>
/// resolved from <see cref="CreationMode"/>, <see cref="WithCheckLogin"/> and <see cref="WithActualLogin"/>.
/// <para>
/// It sets the password of any user: this is provisioning, an administration command (an authentication center is a
/// login point, not an administration point). A high-value action: it requires the
/// <see cref="ICommandAuthCritical">Critical</see> level (a recent login), never reachable by a calling party alone.
/// </para>
/// </summary>
public interface ICreateOrUpdatePasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the target user identifier.
    /// </summary>
    public int UserId { get; set; }

    /// <summary>
    /// Gets or sets the password to set.
    /// </summary>
    public string Password { get; set; }

    /// <summary>
    /// Gets or sets the creation mode. Defaults to <see cref="CreationMode.CreateOrUpdate"/>.
    /// </summary>
    public CreationMode CreationMode { get; set; }

    /// <summary>
    /// Gets or sets whether login checks should be performed without triggering login side effects.
    /// Maps to <c>UCLMode.WithCheckLogin</c>.
    /// </summary>
    public bool WithCheckLogin { get; set; }

    /// <summary>
    /// Gets or sets whether the operation should be treated as an actual login,
    /// performing login checks and triggering side effects (e.g. updating LastLoginTime).
    /// Maps to <c>UCLMode.WithActualLogin</c>.
    /// </summary>
    public bool WithActualLogin { get; set; }
}
