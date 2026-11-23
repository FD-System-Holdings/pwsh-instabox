if (-not ('Instabox.InstaboxApiException' -as [type])) {
    Add-Type -TypeDefinition @'
using System;

namespace Instabox
{
    public class InstaboxApiException : Exception
    {
        public int StatusCode { get; set; }
        public string Code { get; set; }
        public string RequestId { get; set; }
        public bool Retryable { get; set; }
        public string OperationId { get; set; }
        public string Reason { get; set; }
        public string Hint { get; set; }
        public string Docs { get; set; }
        public string DocsUrl { get; set; }
        public string[] RequiredScopes { get; set; }
        public int? RetryAfterSeconds { get; set; }
        public string At { get; set; }
        public string RawBody { get; set; }

        public InstaboxApiException(string message) : base(message)
        {
            Code = string.Empty;
            RequestId = string.Empty;
            OperationId = string.Empty;
            Reason = string.Empty;
            Hint = string.Empty;
            Docs = string.Empty;
            DocsUrl = string.Empty;
            RequiredScopes = Array.Empty<string>();
            At = string.Empty;
            RawBody = string.Empty;
        }

        public InstaboxApiException(string message, Exception innerException) : base(message, innerException)
        {
            Code = string.Empty;
            RequestId = string.Empty;
            OperationId = string.Empty;
            Reason = string.Empty;
            Hint = string.Empty;
            Docs = string.Empty;
            DocsUrl = string.Empty;
            RequiredScopes = Array.Empty<string>();
            At = string.Empty;
            RawBody = string.Empty;
        }

        public override string ToString()
        {
            var req = string.IsNullOrEmpty(RequestId) ? "" : $" [requestId={RequestId}]";
            return $"InstaboxApiException ({StatusCode} {Code}): {Message}{req}";
        }
    }
}
'@
}
