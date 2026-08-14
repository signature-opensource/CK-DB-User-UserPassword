using CK.Core;

namespace CK.DB.User.UserPassword.Reset;

/// <summary>
/// Package that adds the temporary password support.
/// <para>
/// It adds the <c>IsTemporary</c> bit to <c>CK.tUserPassword</c>, feeds it from
/// <c>CK.sUserPasswordUCL</c> and exposes it on the user profile through
/// <c>CK.sUserUserProfileRead</c> as <c>IsTemporaryPassword</c>.
/// </para>
/// </summary>
// Note: "transform:sUserPasswordUCL" is NOT declared here. The transformer is already
// contributed by UserPasswordResetTable through its [SqlProcedure( "transform:sUserPasswordUCL" )]
// method: declaring it here too would apply Res/sUserPasswordUCL.tql twice and the setup would
// fail with "the variable name '@IsTemporary' has already been declared".
[SqlPackage( Schema = "CK", ResourcePath = "Res" )]
[Versions( "1.0.0" )]
[SqlObjectItem( "transform:sUserUserProfileRead" )]
public abstract class Package : SqlPackage
{
    void StObjConstruct( UserPassword.Package basePackage, Actor.Package actorPackage )
    {
    }
}
