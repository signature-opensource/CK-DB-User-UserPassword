using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using CK.Testing;
using Shouldly;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;


namespace CK.DB.User.UserPassword.Tests;

[TestFixture]
public class UserPasswordTests
{

    [Test]
    public void standard_generic_tests_for_Basic_provider()
    {
        var auth = SharedEngine.Map.StObjs.Obtain<Auth.Package>();
        CK.DB.Auth.Tests.AuthTests.StandardTestForGenericAuthenticationProvider(
            auth,
            "Basic",
            payloadForCreateOrUpdate: ( userId, userName ) => "pwd",
            payloadForLogin: ( userId, userName ) => Tuple.Create( userId, "pwd" ),
            payloadForLoginFail: ( userId, userName ) => Tuple.Create( userId, "PWD" )
            );
    }

    [Test]
    public void Generic_to_Basic_provider_with_userId_as_double_or_as_string()
    {
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        var auth = SharedEngine.Map.StObjs.Obtain<Auth.Package>();
        var basic = auth.FindProvider( "Basic" );
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            var userName = Guid.NewGuid().ToString();
            var userId = user.CreateUser( ctx, 1, userName );
            basic.CreateOrUpdateUser( ctx, 1, userId, "pass" ).OperationResult.ShouldBe( UCResult.Created );
            var payload = new Dictionary<string, object>();
            payload["password"] = "pass";

            payload["userId"] = (double)userId;
            basic.LoginUser( ctx, payload ).IsSuccess.ShouldBeTrue();

            payload["userId"] = userId.ToString();
            basic.LoginUser( ctx, payload ).IsSuccess.ShouldBeTrue();
            user.DestroyUser( ctx, 1, userId );
        }
    }

    public async Task standard_generic_tests_for_Basic_provider_Async()
    {
        var auth = SharedEngine.Map.StObjs.Obtain<Auth.Package>();
        await Auth.Tests.AuthTests.StandardTestForGenericAuthenticationProviderAsync(
            auth,
            "Basic",
            payloadForCreateOrUpdate: ( userId, userName ) => "pwd",
            payloadForLogin: ( userId, userName ) => Tuple.Create( userId, "pwd" ),
            payloadForLoginFail: ( userId, userName ) => Tuple.Create( userId, "PWD" )
            );
    }

    [Test]
    public async Task standard_generic_tests_for_Basic_provider_Async_with_migrator_Async()
    {
        var auth = SharedEngine.Map.StObjs.Obtain<Auth.Package>();
        var p = SharedEngine.Map.StObjs.Obtain<Package>();
        using( Util.CreateDisposableAction( () => p.PasswordMigrator = null ) )
        {
            p.PasswordMigrator = new MigrationSupport( 0, "" );
            await Auth.Tests.AuthTests.StandardTestForGenericAuthenticationProviderAsync(
                auth,
                "Basic",
                payloadForCreateOrUpdate: ( userId, userName ) => "pwd",
                payloadForLogin: ( userId, userName ) => Tuple.Create( userId, "pwd" ),
                payloadForLoginFail: ( userId, userName ) => Tuple.Create( userId, "PWD" )
                );
        }
    }


    [Test]
    public void create_password_and_check_Verify_method()
    {
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            var userName = Guid.NewGuid().ToString();
            int userId = user.CreateUser( ctx, 1, userName );
            var pwd = "pwddetestcrrr";
            var pwd2 = "pwddetestcrdfezfrefzzfrr";

            u.CreateOrUpdatePasswordUser( ctx, 1, userId, pwd ).OperationResult.ShouldBe( UCResult.Created );
            u.LoginUser( ctx, userId, pwd ).UserId.ShouldBe( userId );
            u.LoginUser( ctx, userId, pwd2 ).UserId.ShouldBe( 0 );

            u.SetPassword( ctx, 1, userId, pwd2 );
            u.LoginUser( ctx, userId, pwd2 ).UserId.ShouldBe( userId );
            u.LoginUser( ctx, userId, pwd ).UserId.ShouldBe( 0 );

        }
    }

    [Test]
    public void create_a_password_for_an_anonymous_user_is_an_error()
    {
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            Util.Invokable( () => u.CreateOrUpdatePasswordUser( ctx, 1, 0, "x" ) ).ShouldThrow<SqlDetailedException>();
            Util.Invokable( () => u.CreateOrUpdatePasswordUser( ctx, 0, 1, "toto" ) ).ShouldThrow<SqlDetailedException>();
            Util.Invokable( () => u.CreateOrUpdatePasswordUser( ctx, 1, 0, "x", UCLMode.UpdateOnly ) ).ShouldThrow<SqlDetailedException>();
            Util.Invokable( () => u.CreateOrUpdatePasswordUser( ctx, 0, 1, "toto", UCLMode.UpdateOnly ) ).ShouldThrow<SqlDetailedException>();
        }
    }

    [Test]
    public void destroying_a_user_destroys_its_PasswordUser_facet()
    {
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            int userId = user.CreateUser( ctx, 1, Guid.NewGuid().ToString() );
            u.CreateOrUpdatePasswordUser( ctx, 1, userId, "pwd" );
            user.DestroyUser( ctx, 1, userId );
            u.Database.ExecuteReader( "select * from CK.tUserPassword where UserId = @0", userId )
                .Rows.ShouldBeEmpty();
        }
    }

    [TestCase( "p" )]
    [TestCase( "deefzrfgebhntjuykilompo^ùp$*pù^mlkjhgf250258p" )]
    public void changing_iteration_count_updates_automatically_the_hash( string pwd )
    {
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            UserPasswordTable.HashIterationCount = 5000;
            var userName = Guid.NewGuid().ToString();
            int userId = user.CreateUser( ctx, 1, userName );
            u.CreateOrUpdatePasswordUser( ctx, 1, userId, pwd );
            var hash1 = u.Database.ExecuteScalar<byte[]>( $"select PwdHash from CK.tUserPassword where UserId={userId}" );

            UserPasswordTable.HashIterationCount = 50000;
            u.LoginUser( ctx, userId, pwd ).UserId.ShouldBe( userId );
            var hash2 = u.Database.ExecuteScalar<byte[]>( $"select PwdHash from CK.tUserPassword where UserId={userId}" );

            hash1.SequenceEqual( hash2 ).ShouldBeFalse( "Hash has been updated." );

            UserPasswordTable.HashIterationCount = UserPasswordTable.DefaultHashIterationCount;
            u.LoginUser( ctx, userId, pwd ).UserId.ShouldBe( userId );
            var hash3 = u.Database.ExecuteScalar<byte[]>( $"select PwdHash from CK.tUserPassword where UserId={userId}" );

            hash1.SequenceEqual( hash3 ).ShouldBeFalse( "Hash has been updated." );
            hash2.SequenceEqual( hash3 ).ShouldBeFalse( "Hash has been updated." );

        }
    }

    [Test]
    public void UserPassword_implements_IBasicAuthenticationProvider()
    {
        var basic = SharedEngine.Map.StObjs.Obtain<IBasicAuthenticationProvider>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            string name = Guid.NewGuid().ToString();
            int userId = user.CreateUser( ctx, 1, name );
            string pwd = "lklkl";
            var result = basic.CreateOrUpdatePasswordUser( ctx, 1, userId, pwd, UCLMode.CreateOnly );
            result.OperationResult.ShouldBe( UCResult.Created );
            result = basic.CreateOrUpdatePasswordUser( ctx, 1, userId, pwd + "no", UCLMode.CreateOnly );
            result.OperationResult.ShouldBe( UCResult.None );
            basic.LoginUser( ctx, userId, pwd ).UserId.ShouldBe( userId );
            basic.LoginUser( ctx, userId, pwd + "no" ).UserId.ShouldBe( 0 );
            basic.LoginUser( ctx, name, pwd ).UserId.ShouldBe( userId );
            basic.LoginUser( ctx, name, pwd + "no" ).UserId.ShouldBe( 0 );
            basic.SetPassword( ctx, 1, userId, (pwd = pwd + "BIS") );
            basic.LoginUser( ctx, userId, pwd ).UserId.ShouldBe( userId );
            basic.LoginUser( ctx, userId, pwd + "no" ).UserId.ShouldBe( 0 );
            basic.LoginUser( ctx, name, pwd ).UserId.ShouldBe( userId );
            basic.LoginUser( ctx, name, pwd + "no" ).UserId.ShouldBe( 0 );
            basic.DestroyPasswordUser( ctx, 1, userId );
            user.Database.ExecuteReader( "select * from CK.tUserPassword where UserId = @0", userId )
                .Rows.ShouldBeEmpty();
            user.DestroyUser( ctx, 1, userId );
        }
    }

    [Test]
    public async Task UserPassword_implements_IBasicAuthenticationProvider_Async()
    {
        var basic = SharedEngine.Map.StObjs.Obtain<IBasicAuthenticationProvider>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            string name = Guid.NewGuid().ToString();
            int userId = await user.CreateUserAsync( ctx, 1, name );
            string pwd = "lklkl";
            var result = await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, userId, pwd, UCLMode.CreateOnly );
            result.OperationResult.ShouldBe( UCResult.Created );
            result = await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, userId, pwd + "no", UCLMode.CreateOnly );
            result.OperationResult.ShouldBe( UCResult.None );
            (await basic.LoginUserAsync( ctx, userId, pwd )).UserId.ShouldBe( userId );
            (await basic.LoginUserAsync( ctx, userId, pwd + "no" )).UserId.ShouldBe( 0 );
            (await basic.LoginUserAsync( ctx, name, pwd )).UserId.ShouldBe( userId );
            (await basic.LoginUserAsync( ctx, name, pwd + "no" )).UserId.ShouldBe( 0 );
            await basic.SetPasswordAsync( ctx, 1, userId, (pwd = pwd + "BIS") );
            (await basic.LoginUserAsync( ctx, userId, pwd )).UserId.ShouldBe( userId );
            (await basic.LoginUserAsync( ctx, userId, pwd + "no" )).UserId.ShouldBe( 0 );
            (await basic.LoginUserAsync( ctx, name, pwd )).UserId.ShouldBe( userId );
            (await basic.LoginUserAsync( ctx, name, pwd + "no" )).UserId.ShouldBe( 0 );
            await basic.DestroyPasswordUserAsync( ctx, 1, userId );
            user.Database.ExecuteReader( "select * from CK.tUserPassword where UserId = @0", userId )
                .Rows.ShouldBeEmpty();
            await user.DestroyUserAsync( ctx, 1, userId );
        }
    }

    class MigrationSupport : IUserPasswordMigrator
    {
        readonly int _userIdToMigrate;
        readonly string _pwd;

        public bool MigrationDoneCalled;

        public MigrationSupport( int userIdToMigrate, string pwd )
        {
            _userIdToMigrate = userIdToMigrate;
            _pwd = pwd;
        }

        public void MigrationDone( ISqlCallContext ctx, int userId ) => MigrationDoneCalled = true;

        public bool VerifyPassword( ISqlCallContext ctx, int userId, string password )
        {
            return userId == _userIdToMigrate && _pwd == password;
        }
    }

    [Test]
    public void password_migration_is_supported_by_user_id_and_user_name()
    {
        var p = SharedEngine.Map.StObjs.Obtain<Package>();
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( Util.CreateDisposableAction( () => p.PasswordMigrator = null ) )
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            // By identifier
            {
                string userName = Guid.NewGuid().ToString();
                var idU = user.CreateUser( ctx, 1, userName );
                p.PasswordMigrator = new MigrationSupport( idU, "toto" );

                u.LoginUser( ctx, idU, "failed" ).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select PwdHash from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( Array.Empty<byte>(), "The row in the table has been created but with an empty hash." );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 1, "Migration is potentially protected by FailedAttemptCount." );

                u.LoginUser( ctx, idU, "failed n°2" ).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU} and PwdHash=0x" )
                    .ShouldBe( 2, "Migration is potentially protected by FailedAttemptCount." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.ShouldBeEmpty( "A failed migration deos not appear in the view." );


                u.LoginUser( ctx, idU, "toto" ).UserId.ShouldBe( idU );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 0, "FailedAttemptCount is zeroed on successful login." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.Count.ShouldBe( 1, "The view now contains the successfully migrated user." );

                u.LoginUser( ctx, idU, "toto" ).UserId.ShouldBe( idU );
            }
            // By user name
            {
                string userName = Guid.NewGuid().ToString();
                var idU = user.CreateUser( ctx, 1, userName );
                p.PasswordMigrator = new MigrationSupport( idU, "toto" );

                u.LoginUser( ctx, userName, "failed" ).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select PwdHash from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( Array.Empty<byte>(), "The row in the table has been created but with an empty hash." );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 1, "Migration is potentially protected by FailedAttemptCount." );

                u.LoginUser( ctx, userName, "failed n°2" ).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU} and PwdHash=0x" )
                    .ShouldBe( 2, "Migration is potentially protected by FailedAttemptCount." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.ShouldBeEmpty( "A failed migration deos not appear in the view." );

                u.LoginUser( ctx, userName, "toto" ).UserId.ShouldBe( idU );
                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.Count.ShouldBe( 1, "The view now contains the successfully migrated user." );


                u.LoginUser( ctx, userName, "toto" ).UserId.ShouldBe( idU );

            }
        }
    }

    [Test]
    public async Task password_migration_is_supported_by_user_id_and_user_name_Async()
    {
        var p = SharedEngine.Map.StObjs.Obtain<Package>();
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( Util.CreateDisposableAction( () => p.PasswordMigrator = null ) )
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            // By identifier
            {
                string userName = Guid.NewGuid().ToString();
                var idU = await user.CreateUserAsync( ctx, 1, userName );
                p.PasswordMigrator = new MigrationSupport( idU, "toto" );

                (await u.LoginUserAsync( ctx, idU, "failed" )).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select PwdHash from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( Array.Empty<byte>(), "The row in the table has been created but with an empty hash." );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 1, "Migration is potentially protected by FailedAttemptCount." );

                (await u.LoginUserAsync( ctx, idU, "failed n°2" )).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU} and PwdHash=0x" )
                    .ShouldBe( 2, "Migration is potentially protected by FailedAttemptCount." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.ShouldBeEmpty( "A failed migration deos not appear in the view." );

                (await u.LoginUserAsync( ctx, idU, "toto" )).UserId.ShouldBe( idU );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 0, "FailedAttemptCount is zeroed on successful login." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.Count.ShouldBe( 1, "The view now contains the successfully migrated user." );

                (await u.LoginUserAsync( ctx, idU, "toto" )).UserId.ShouldBe( idU );
            }
            // By user name
            {
                string userName = Guid.NewGuid().ToString();
                var idU = await user.CreateUserAsync( ctx, 1, userName );
                p.PasswordMigrator = new MigrationSupport( idU, "toto" );

                (await u.LoginUserAsync( ctx, userName, "failed" )).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select PwdHash from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( Array.Empty<byte>(), "The row in the table has been created but with an empty hash." );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 1, "Migration is potentially protected by FailedAttemptCount." );

                (await u.LoginUserAsync( ctx, userName, "failed n°2" )).UserId.ShouldBe( 0 );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU} and PwdHash=0x" )
                    .ShouldBe( 2, "Migration is potentially protected by FailedAttemptCount." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.ShouldBeEmpty( "A failed migration deos not appear in the view." );

                (await u.LoginUserAsync( ctx, userName, "toto" )).UserId.ShouldBe( idU );
                p.Database.ExecuteScalar( $"select FailedAttemptCount from CK.tUserPassword where UserId={idU}" )
                    .ShouldBe( 0, "FailedAttemptCount is zeroed on successful login." );

                u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                    .Rows.Count.ShouldBe( 1, "The view now contains the successfully migrated user." );

                (await u.LoginUserAsync( ctx, userName, "toto" )).UserId.ShouldBe( idU );
            }
        }
    }

    [Test]
    public void onLogin_extension_point_is_called()
    {
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            // By name
            {
                string userName = Guid.NewGuid().ToString();
                var idU = user.CreateUser( ctx, 1, userName );
                var baseTime = u.Database.ExecuteScalar<DateTime>( "select sysutcdatetime();" );
                u.CreateOrUpdatePasswordUser( ctx, 1, idU, "password", UCLMode.CreateOrUpdate | UCLMode.WithActualLogin );
                var firstTime = u.Database.ExecuteScalar<DateTime>( $"select LastLoginTime from CK.tUserPassword where UserId={idU}" );
                firstTime.ShouldBe( baseTime, tolerance: TimeSpan.FromSeconds( 1 ) );
                Thread.Sleep( 100 );
                u.LoginUser( ctx, userName, "failed login", actualLogin: true ).UserId.ShouldBe( 0 );
                var firstTimeNo = u.Database.ExecuteScalar<DateTime>( $"select LastLoginTime from CK.tUserPassword where UserId={idU}" );
                firstTimeNo.ShouldBe( firstTime );
                u.LoginUser( ctx, userName, "password", actualLogin: true ).UserId.ShouldBe( idU );
                var firstTimeYes = u.Database.ExecuteScalar<DateTime>( $"select LastLoginTime from CK.tUserPassword where UserId={idU}" );
                firstTimeYes.ShouldBeGreaterThan( firstTimeNo );
            }
        }
    }

    [Test]
    public void Basic_AuthProvider_is_registered()
    {
        Auth.Tests.AuthTests.CheckProviderRegistration( "Basic" );
    }

    [Test]
    public void vUserAuthProvider_reflects_the_user_basic_authentication()
    {
        var u = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>();
        var user = SharedEngine.Map.StObjs.Obtain<UserTable>();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            string userName = "Basic auth - " + Guid.NewGuid().ToString();
            var idU = user.CreateUser( ctx, 1, userName );
            u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                .Rows.ShouldBeEmpty();
            u.CreateOrUpdatePasswordUser( ctx, 1, idU, "password" );
            u.Database.ExecuteScalar( $"select count(*) from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                .ShouldBe( 1 );
            u.DestroyPasswordUser( ctx, 1, idU );
            u.Database.ExecuteReader( $"select * from CK.vUserAuthProvider where UserId={idU} and Scheme='Basic'" )
                .Rows.ShouldBeEmpty();
            // To let the use in the database with a basic authentication.
            u.CreateOrUpdatePasswordUser( ctx, 1, idU, "password" );
        }
    }

}
