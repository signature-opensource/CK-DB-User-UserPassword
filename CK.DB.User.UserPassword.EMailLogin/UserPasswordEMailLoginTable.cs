using CK.Core;
using CK.SqlServer;
using Microsoft.Data.SqlClient;

namespace CK.DB.User.UserPassword.EMailLogin;

/// <summary>
/// Specializes <see cref="UserPassword.UserPasswordTable"/> so that the "Basic" login by name
/// also accepts a validated email address (from <c>CK.tActorEMail</c>) as the login identifier.
/// <para>
/// Being the most specialized <c>tUserPassword</c> object, this table becomes the single
/// <see cref="Auth.IBasicAuthenticationProvider"/> instance of any application that references this package.
/// </para>
/// </summary>
[SqlTable( "tUserPassword", Package = typeof( Package ) )]
[Versions( "1.0.0" )]
public abstract class UserPasswordEMailLoginTable : UserPassword.UserPasswordTable
{
    // Ensures CK.tActorEMail is set up before this table (setup ordering + package inclusion).
    void StObjConstruct( Actor.ActorEMail.ActorEMailTable emailTable )
    {
    }

    /// <summary>
    /// Overridden to resolve the login identifier by <c>UserName</c> OR by the actor's primary and
    /// validated email in <c>CK.tActorEMail</c> (<c>IsPrimary = 1</c> and <c>ValTime</c> greater than
    /// the default '0001-01-01' means primary and validated).
    /// The <c>UserName</c> match is prioritized and <c>top 1</c> guarantees the single row required by
    /// the verification path even in the edge case where a <c>UserName</c> equals another actor's email.
    /// The returned columns (PwdHash, UserId, FailedAttemptCount) and their order are kept identical to
    /// the base command so the password verification logic is unchanged.
    /// </summary>
    protected override SqlCommand CreateReadByNameCommand( string userName )
    {
        var c = new SqlCommand(
            "select top 1 p.PwdHash, u.UserId, p.FailedAttemptCount " +
            "from CK.tUser u " +
            "left outer join CK.tUserPassword p on p.UserId = u.UserId " +
            "where u.UserName = @Key " +
            "   or u.UserId in (select e.ActorId from CK.tActorEMail e where e.EMail = @Key and e.IsPrimary = 1 and e.ValTime > '0001-01-01') " +
            "order by case when u.UserName = @Key then 0 else 1 end" );
        c.Parameters.AddWithValue( "@Key", userName );
        return c;
    }
}
