using System.Numerics;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;

namespace Crossdyne.Security.Tests.Helpers
{
    public static class SrpHelper
    {
        public static SrpContext GetSrpContext()
        {
            SrpProfile profile = SrpProfileRegistry.GetProfile(SrpGroup.Rfc5054_8192); 

            var srpContext = SrpContext.FromOptions(profile.Options);
            // var srpContext = new SrpContext(
            //     N: profile.Options.N,
            //     G: new BigInteger(profile.Options.G), 
            //     K: profile.Options.ComputeK(),
            //     ModulusSize: profile.Options.ModulusSize,
            //     HashAlgorithmName: profile.HashAlgorithm,
            //     HashSize: hashSize
            // );

            return srpContext;
        }
    }
}