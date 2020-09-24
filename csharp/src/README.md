# C# wrapper for CECIES
## This is a **netstandard2.1** wrapper around CECIES

In order to use this, just copy the [`CeciesSharpContext`](https://github.com/GlitchedPolygons/cecies/blob/master/csharp/CeciesSharp/src/CeciesSharp.cs#L12) 
class into your own C# project and manually copy the [`CeciesSharp/src/lib`](https://github.com/GlitchedPolygons/cecies/tree/master/csharp/CeciesSharp/src/lib) folder into your
own project's build output directory (otherwise the `CeciesSharpContext` wrapper class doesn't know where to load the DLL/shared lib from; it needs to be in that specific path).

**Note:** the library files inside the [`CeciesSharp/src/lib`](https://github.com/GlitchedPolygons/cecies/tree/master/csharp/CeciesSharp/src/lib) folder were taken from the [2.1.3 release](https://github.com/GlitchedPolygons/cecies/releases/tag/2.1.3) archives.
