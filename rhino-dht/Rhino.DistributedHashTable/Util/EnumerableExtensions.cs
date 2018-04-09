using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Rhino.DistributedHashTable.Util
{
	public static class EnumerableExtensions
	{
		public static IEnumerable<T> Apply<T>(this IEnumerable<T> self, Action<T> action)
		{
			foreach (var item in self)
			{
				action(item);
				yield return item;
			}
		}

		public static HashSet<T> ToSet<T>(this IEnumerable<T> self)
		{
			return new HashSet<T>(self);
		}


		public static void MoveTo<T>(this ICollection<T> self, ICollection<T> other, Func<T, bool> predicate)
		{
			var array = self.Where(predicate).ToArray();
			foreach (var item in array)
			{
				self.Remove(item);
				other.Add(item);
			}
		}

		public static void RemoveAll<T>(this ICollection<T> self, Func<T, bool> predicate)
		{
			var array = self.Where(predicate).ToArray();
			foreach (var item in array)
			{
				self.Remove(item);
			}
		}

		public static IEnumerable<T> Append<T>(this IEnumerable<T> self, T item) where T : class
		{
			foreach (var i in self)
			{
				yield return i;
			}
			if (item != null)
				yield return item;
		}

		public static bool Empty(this IEnumerable self)
		{
			foreach (var _ in self)
			{
				return false;
			}
			return true;
		}

		public static void Consume(this IEnumerable self)
		{
			foreach (var _ in self)
			{
			}
		}
	}
}