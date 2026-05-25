@echo off
REM Run from the directory that contains your shader sources or adapt paths.
glslc raster.vert -o ../build/raster.vert.spv
glslc gbuffer.frag -o ../build/gbuffer.frag.spv
glslc raster.frag -o ../build/raster.frag.spv
glslc rt_lighting.comp -o ../build/rt_lighting.comp.spv
glslc rt_spatial.comp -o ../build/rt_spatial.comp.spv
glslc rt_temporal.comp -o ../build/rt_temporal.comp.spv
glslc rt_composite.comp -o ../build/rt_composite.comp.spv
glslc raycast.comp -o ../build/raycast.comp.spv