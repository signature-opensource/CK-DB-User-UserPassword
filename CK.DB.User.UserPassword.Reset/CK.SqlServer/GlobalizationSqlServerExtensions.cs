using CK.SqlServer;
using System.Linq;
using System.Runtime.CompilerServices;

namespace CK.Core;

static class GlobalizationSqlServerExtensions
{
    public static UserMessage Error( this UserMessageCollector collector, SqlDetailedException sqlEx, [CallerFilePath] string? filePath = null, [CallerLineNumber] int lineNumber = 0 )
    {
        var innerMessage = sqlEx.InnerSqlException?.Message ?? "Unknown SQLError";

        if( innerMessage.Contains( "||" ) )
        {
            var parts = innerMessage.Split( "||", 2 );
            var message = parts.ElementAtOrDefault( 0 ) ?? "Unknown SQL error";
            var key = parts.ElementAtOrDefault( 1 ) ?? "SQLError.NotSpecified";
            return collector.Error( message, key, filePath, lineNumber );
        }

        return collector.Error( innerMessage, innerMessage, filePath, lineNumber );
    }
}
