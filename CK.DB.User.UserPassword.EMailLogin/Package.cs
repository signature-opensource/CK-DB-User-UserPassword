using CK.Core;

namespace CK.DB.User.UserPassword.EMailLogin;

/// <summary>
/// Package that enables login by email address for the "Basic" authentication provider.
/// It specializes <see cref="UserPassword.UserPasswordTable"/> (see <see cref="UserPasswordEMailLoginTable"/>)
/// so that the login identifier is resolved against <c>CK.tActorEMail</c> in addition to <c>CK.tUser.UserName</c>.
/// </summary>
[SqlPackage( Schema = "CK" )]
[Versions( "1.0.0" )]
public abstract class Package : SqlPackage
{
    void StObjConstruct( UserPassword.Package basePackage, Actor.ActorEMail.Package emailPackage )
    {
    }
}
