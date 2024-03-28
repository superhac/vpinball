$input a_position, a_normal, a_texcoord0
$output v_worldPos, v_normal, v_texcoord0

#include "common.sh"

uniform mat4 orientation;
uniform mat4 matWorldView;
uniform mat4 matWorldViewInverse;
uniform mat4 matWorldViewProj;


void main()
{
	// apply spinning and move the ball to it's actual position
	vec4 pos = vec4(a_position, 1.0);
	pos.xyz = mul(orientation, pos).xyz;

	// apply spinning to the normals too to get the sphere mapping effect
	const vec3 nspin = mul(orientation, vec4(a_normal, 0.0)).xyz;
    // Needs to use a 'normal' matrix, and to normalize since we allow non uniform stretching, therefore matWorldView is not orthonormal
	v_normal = normalize(mul(vec4(nspin, 0.0), matWorldViewInverse).xyz); // actually: mul(vec4(nspin,0.), matWorldViewInverseTranspose), but optimized to save one matrix

	v_texcoord0 = a_texcoord0;
	v_worldPos = mul(matWorldView, pos).xyz;
	gl_Position = mul(matWorldViewProj, pos);
}