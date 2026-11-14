
1. 根据 design 得到 impl  

@DESIGN.md  请根据以上信息，制订一个论文prototype实现计划，我们需要支持linux kernel / userpsace (servers) / freeBSD等任何系统漏洞的攻击拦截，但是不过度工程化，只是一个论文最简原型。我们已经有了自己的eBPF虚拟机（和uBPF类似）。请用简洁语言给出我们的实现方案，例如：分为几个模块，每个模块怎么实现，怎么测试？
这不是论文写作，而是用于AI Coding实现，请用最简单的语言给出方案，不要用bullet来方便阅读，我需要逐条逐字人工核对。

2. 根据 impl 制订开发计划   

@DESIGN.md  
@IMPL.md  
参考设计和实现思路，制定一个ai coding开发计划。一切是为了发论文，所以按照论文的Prototype的风格来就行，不用考了太多工程的完备性，一切都是为了简单简洁，最少代码实现功能，目录和模块划分清晰合理，方便人来阅读。

## v0.2 Local Policy Compiler Prompt

The official policy-generation prompt is stored at `tools/policy/prompts/policy_generation.md`.

Usage notes:
- The prompt asks the model for YAML metadata plus a fenced DSL block only.
- The model must not generate arbitrary Python, kernel code, imports, direct target function calls, or mirror function bodies.
- Shadow/mirror helpers are declared through `@shadow` or `shadow_call`; VulGate controls the resource model and verification.
- All generated bundles are local release artifacts until reviewed. Do not submit local changes or release artifacts to GitHub.
