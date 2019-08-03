// A simple version implementation based on 
// https://github.com/maxhauser/semver/blob/master/src/Semver/SemVersion.cs
// MIT License
// Copyright (c) 2013 Max Hauser 
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Globalization;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Text.RegularExpressions;

namespace Elastic 
{
    /// <summary>
    /// An Elastic product version
    /// </summary>
    public sealed class ElasticVersion : IEquatable<ElasticVersion>, IComparable<ElasticVersion>, IComparable
    {
        private static Regex VersionRegex = new Regex(
            @"^(?<major>\d+)(\.(?<minor>\d+))?(\.(?<patch>\d+))?(\-(?<pre>[0-9A-Za-z]+))?$", 
            RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture);

        public ElasticVersion(object version) : this(version.ToString())
        {
        }

        public ElasticVersion(string version)
        {
            var match = VersionRegex.Match(version);
            if (!match.Success)
                throw new ArgumentException(string.Format("Invalid version '{0}'", version), "version");

            var major = int.Parse(match.Groups["major"].Value, CultureInfo.InvariantCulture);

            var minorMatch = match.Groups["minor"];
            int minor = 0;
            if (minorMatch.Success) 
                minor = int.Parse(minorMatch.Value, CultureInfo.InvariantCulture);

            var patchMatch = match.Groups["patch"];
            int patch = 0;
            if (patchMatch.Success)
                patch = int.Parse(patchMatch.Value, CultureInfo.InvariantCulture);

            var prerelease = match.Groups["pre"].Value;
            
            this.Major = major;
            this.Minor = minor;
            this.Patch = patch;
            this.Prerelease = prerelease;
        }

        public ElasticVersion(int major, int minor, int patch, string prerelease)
        {
            this.Major = major;
            this.Minor = minor;
            this.Patch = patch;
            this.Prerelease = prerelease;
        }

        public static bool TryParse(string version, out ElasticVersion ElasticVersion)
        {
            try
            {
                ElasticVersion = new ElasticVersion(version);
                return true;
            }
            catch (Exception)
            {
                ElasticVersion = null;
                return false;
            }
        }

        public static bool Equals(ElasticVersion versionA, ElasticVersion versionB)
        {
            if (ReferenceEquals(versionA, null))
                return ReferenceEquals(versionB, null);
            return versionA.Equals(versionB);
        }

        public static int Compare(ElasticVersion versionA, ElasticVersion versionB)
        {
            if (ReferenceEquals(versionA, null))
                return ReferenceEquals(versionB, null) ? 0 : -1;
            return versionA.CompareTo(versionB);
        }

        public ElasticVersion Change(int? major = null, int? minor = null, int? patch = null, string prerelease = null)
        {
            return new ElasticVersion(
                major ?? this.Major,
                minor ?? this.Minor,
                patch ?? this.Patch,
                prerelease ?? this.Prerelease);
        }

        public int Major { get; private set; }

        public int Minor { get; private set; }

        public int Patch { get; private set; }

        public string Prerelease { get; private set; }

        public override string ToString()
        {
            var version = "" + Major + "." + Minor + "." + Patch;
            if (!String.IsNullOrEmpty(Prerelease))
                version += "-" + Prerelease;
            return version;
        }

        public int CompareTo(object obj)
        {
            return CompareTo((ElasticVersion)obj);
        }

        public int CompareTo(ElasticVersion other)
        {
            if (ReferenceEquals(other, null))
                return 1;

            var r = this.CompareByPrecedence(other);
            return r;
        }

        public bool PrecedenceMatches(ElasticVersion other)
        {
            return CompareByPrecedence(other) == 0;
        }

        public int CompareByPrecedence(ElasticVersion other)
        {
            if (ReferenceEquals(other, null))
                return 1;

            var r = this.Major.CompareTo(other.Major);
            if (r != 0) return r;

            r = this.Minor.CompareTo(other.Minor);
            if (r != 0) return r;

            r = this.Patch.CompareTo(other.Patch);
            if (r != 0) return r;

            r = CompareComponent(this.Prerelease, other.Prerelease, true);
            return r;
        }

        static int CompareComponent(string a, string b, bool lower = false)
        {
            var aEmpty = String.IsNullOrEmpty(a);
            var bEmpty = String.IsNullOrEmpty(b);
            if (aEmpty && bEmpty)
                return 0;

            if (aEmpty)
                return lower ? 1 : -1;
            if (bEmpty)
                return lower ? -1 : 1;

            var aComps = a.Split('.');
            var bComps = b.Split('.');

            var minLen = Math.Min(aComps.Length, bComps.Length);
            for (int i = 0; i < minLen; i++)
            {
                var ac = aComps[i];
                var bc = bComps[i];
                int anum, bnum;
                var isanum = Int32.TryParse(ac, out anum);
                var isbnum = Int32.TryParse(bc, out bnum);
                int r;
                if (isanum && isbnum)
                {
                    r = anum.CompareTo(bnum);
                    if (r != 0) return anum.CompareTo(bnum);
                }
                else
                {
                    if (isanum)
                        return -1;
                    if (isbnum)
                        return 1;
                    r = String.CompareOrdinal(ac, bc);
                    if (r != 0)
                        return r;
                }
            }

            return aComps.Length.CompareTo(bComps.Length);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(obj, null))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            var other = (ElasticVersion)obj;

            return Equals(other);
        }

        public bool Equals(ElasticVersion other)
        {
            if (other == null)
                return false;

            return this.Major == other.Major &&
                this.Minor == other.Minor &&
                this.Patch == other.Patch &&
                string.Equals(this.Prerelease, other.Prerelease, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int result = this.Major.GetHashCode();
                result = result * 31 + this.Minor.GetHashCode();
                result = result * 31 + this.Patch.GetHashCode();
                result = result * 31 + this.Prerelease.GetHashCode();
                return result;
            }
        }

        public static bool operator ==(ElasticVersion left, ElasticVersion right)
        {
            return ElasticVersion.Equals(left, right);
        }

        public static bool operator !=(ElasticVersion left, ElasticVersion right)
        {
            return !ElasticVersion.Equals(left, right);
        }

        public static bool operator >(ElasticVersion left, ElasticVersion right)
        {
            return ElasticVersion.Compare(left, right) > 0;
        }

        public static bool operator >=(ElasticVersion left, ElasticVersion right)
        {
            return left == right || left > right;
        }

        public static bool operator <(ElasticVersion left, ElasticVersion right)
        {
            return ElasticVersion.Compare(left, right) < 0;
        }

        public static bool operator <=(ElasticVersion left, ElasticVersion right)
        {
            return left == right || left < right;
        }
    }
}
