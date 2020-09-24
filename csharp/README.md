# C# wrapper for CECIES
## This is a **netstandard2.1** wrapper around CECIES

In order to use this, just copy the [`CeciesSharpContext`](https://github.com/GlitchedPolygons/cecies/blob/master/csharp/CeciesSharp/src/CeciesSharp.cs) 
class into your own C# project and manually copy the [`lib/`](https://github.com/GlitchedPolygons/cecies/tree/master/csharp/lib) folder into your
own project's build output directory (otherwise the `CeciesSharpContext` wrapper class doesn't know where to load the DLL/shared lib from; it needs to be in that specific path).
