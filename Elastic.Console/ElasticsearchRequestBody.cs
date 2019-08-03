using System;
using System.Collections;

namespace Elastic 
{
    /// <summary>
    /// An Elasticsearch API request body represented as a
    /// Hashtable or string
    /// </summary>
    /// <remarks>
    /// Allows $Body in Invoke-Elasticsearch to *not* bind to ElasticsearchRequest
    /// </remarks>
    public class ElasticsearchRequestBody
    {
        public ElasticsearchRequestBody(Hashtable input)
        {
            this.Input = input;
        }

        public ElasticsearchRequestBody(string input)
        {
            this.Input = input;
        }

        public object Input { get; private set; }
    }
}