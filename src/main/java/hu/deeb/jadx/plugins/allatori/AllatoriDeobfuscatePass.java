package hu.deeb.jadx.plugins.allatori;

import jadx.api.plugins.pass.JadxPassInfo;
import jadx.api.plugins.pass.impl.OrderedJadxPassInfo;
import jadx.api.plugins.pass.types.JadxDecompilePass;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.ArithNode;
import jadx.core.dex.instructions.ArithOp;
import jadx.core.dex.instructions.ConstStringNode;
import jadx.core.dex.instructions.InvokeNode;
import jadx.core.dex.instructions.InsnType;
import jadx.core.dex.instructions.args.ArgType;
import jadx.core.dex.instructions.args.InsnArg;
import jadx.core.dex.instructions.args.LiteralArg;
import jadx.core.dex.instructions.args.RegisterArg;
import jadx.core.dex.nodes.BlockNode;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.InsnNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.dex.nodes.RootNode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AllatoriDeobfuscatePass implements JadxDecompilePass {
	private static final String ALLATORI_METHOD = "ALLATORIxDEMO";
	private static final DecodeKeys DEFAULT_KEYS = new DecodeKeys(0, 0);

	private final Map<MethodInfo, DecodeKeys> keysCache = new HashMap<>();

	@Override
	public JadxPassInfo getInfo() {
		return new OrderedJadxPassInfo(
				"AllatoriDeobfuscate",
				"Replace known Allatori string decrypt calls with decoded string constants")
				.after("SSATransform")
				.after("MarkFinallyVisitor")
				.before("ConstInlineVisitor");
	}

	@Override
	public void init(RootNode rootNode) {
	}

	@Override
	public boolean visit(ClassNode classNode) {
		return true;
	}

	@Override
	public void visit(MethodNode methodNode) {
		if (methodNode.isNoCode()) {
			return;
		}
		List<BlockNode> blocks = methodNode.getBasicBlocks();
		if (blocks == null) {
			return;
		}
		cacheDecodeKeys(methodNode);
		for (BlockNode block : blocks) {
			List<InsnNode> instructions = block.getInstructions();
			for (int i = 0; i < instructions.size(); i++) {
				InsnNode insn = instructions.get(i);
				replaceWrappedDecryptCalls(methodNode, insn);
				InsnNode replacement = decodeInvoke(methodNode, insn);
				if (replacement != null) {
					instructions.set(i, replacement);
				}
			}
		}
	}

	private void cacheDecodeKeys(MethodNode methodNode) {
		MethodInfo methodInfo = methodNode.getMethodInfo();
		if (!isAllatoriDecryptMethod(methodInfo)) {
			return;
		}
		DecodeKeys keys = extractDecodeKeys(methodNode);
		if (keys != null) {
			keysCache.put(methodInfo, keys);
		}
	}

	private void replaceWrappedDecryptCalls(MethodNode methodNode, InsnNode insn) {
		for (InsnArg arg : insn.getArgList()) {
			InsnArg replacement = decodeWrappedInvoke(methodNode, arg);
			if (replacement != null) {
				insn.replaceArg(arg, replacement);
			} else if (arg.isInsnWrap()) {
				replaceWrappedDecryptCalls(methodNode, arg.unwrap());
			}
		}
	}

	private InsnNode decodeInvoke(MethodNode methodNode, InsnNode insn) {
		if (insn.getType() != InsnType.INVOKE || !(insn instanceof InvokeNode)) {
			return null;
		}
		InvokeNode invoke = (InvokeNode) insn;
		if (!isAllatoriDecryptCall(invoke) || invoke.getResult() == null || invoke.getArgsCount() != 1) {
			return null;
		}
		String encoded = getConstString(invoke.getArg(0));
		if (encoded == null) {
			return null;
		}
		DecodeKeys keys = getDecodeKeys(methodNode, invoke);
		if (keys == null) {
			return null;
		}
		ConstStringNode constString = new ConstStringNode(decodeAllatoriString(encoded, keys));
		constString.setResult(invoke.getResult());
		constString.copyAttributesFrom(invoke);
		return constString;
	}

	private InsnArg decodeWrappedInvoke(MethodNode methodNode, InsnArg arg) {
		if (!arg.isInsnWrap()) {
			return null;
		}
		InsnNode wrappedInsn = arg.unwrap();
		if (wrappedInsn.getType() != InsnType.INVOKE || !(wrappedInsn instanceof InvokeNode)) {
			return null;
		}
		InvokeNode invoke = (InvokeNode) wrappedInsn;
		if (!isAllatoriDecryptCall(invoke) || invoke.getArgsCount() != 1) {
			return null;
		}
		String encoded = getConstString(invoke.getArg(0));
		if (encoded == null) {
			return null;
		}
		DecodeKeys keys = getDecodeKeys(methodNode, invoke);
		if (keys == null) {
			return null;
		}
		ConstStringNode constString = new ConstStringNode(decodeAllatoriString(encoded, keys));
		constString.copyAttributesFrom(invoke);
		InsnArg constArg = InsnArg.wrapArg(constString);
		constArg.setType(ArgType.STRING);
		return constArg;
	}

	private static boolean isAllatoriDecryptCall(InvokeNode invoke) {
		if (!invoke.isStaticCall()) {
			return false;
		}
		MethodInfo callMethod = invoke.getCallMth();
		return isAllatoriDecryptMethod(callMethod);
	}

	private static boolean isAllatoriDecryptMethod(MethodInfo callMethod) {
		return ALLATORI_METHOD.equals(callMethod.getName())
				&& callMethod.getArgsCount() == 1
				&& "java.lang.String".equals(callMethod.getArgumentsTypes().get(0).getObject())
				&& "java.lang.String".equals(callMethod.getReturnType().getObject());
	}

	private static String getConstString(InsnArg arg) {
		if (arg.isInsnWrap()) {
			return getConstString(arg.unwrap());
		}
		if (arg instanceof RegisterArg) {
			return getConstString(((RegisterArg) arg).getAssignInsn());
		}
		return null;
	}

	private static String getConstString(InsnNode insn) {
		if (insn instanceof ConstStringNode) {
			return ((ConstStringNode) insn).getString();
		}
		return null;
	}

	private DecodeKeys getDecodeKeys(MethodNode callerMethod, InvokeNode invoke) {
		MethodInfo callMethod = invoke.getCallMth();
		DecodeKeys cachedKeys = keysCache.get(callMethod);
		if (cachedKeys != null) {
			return cachedKeys;
		}
		MethodNode decryptMethod = callerMethod.root().getMethodUtils().resolveMethod(invoke);
		DecodeKeys keys = extractDecodeKeys(decryptMethod);
		if (keys != null) {
			keysCache.put(callMethod, keys);
		}
		return keys;
	}

	private static DecodeKeys extractDecodeKeys(MethodNode decryptMethod) {
		if (decryptMethod == null || decryptMethod.isNoCode() || decryptMethod.getBasicBlocks() == null) {
			return null;
		}
		Integer firstXorKey = null;
		for (BlockNode block : decryptMethod.getBasicBlocks()) {
			for (InsnNode insn : block.getInstructions()) {
				Integer xorKey = getXorLiteral(insn);
				if (xorKey == null) {
					continue;
				}
				if (firstXorKey == null) {
					firstXorKey = xorKey;
				} else if (!firstXorKey.equals(xorKey)) {
					return new DecodeKeys(firstXorKey, xorKey);
				}
			}
		}
		return null;
	}

	private static Integer getXorLiteral(InsnNode insn) {
		if (!(insn instanceof ArithNode) || ((ArithNode) insn).getOp() != ArithOp.XOR) {
			return null;
		}
		List<InsnArg> args = insn.getArgList();
		for (int i = 0; i < args.size(); i++) {
			if (!isStringCharAtResult(args.get(i))) {
				continue;
			}
			for (int j = 0; j < args.size(); j++) {
				if (i == j) {
					continue;
				}
				Integer key = evalConstInt(args.get(j));
				if (key != null) {
					return key;
				}
			}
		}
		return null;
	}

	private static boolean isStringCharAtResult(InsnArg arg) {
		if (arg.isInsnWrap()) {
			return isStringCharAtInsn(arg.unwrap());
		}
		if (arg instanceof RegisterArg) {
			return isStringCharAtInsn(((RegisterArg) arg).getAssignInsn());
		}
		return false;
	}

	private static boolean isStringCharAtInsn(InsnNode insn) {
		if (insn == null) {
			return false;
		}
		if (insn.getType() == InsnType.MOVE && insn.getArgsCount() == 1) {
			return isStringCharAtResult(insn.getArg(0));
		}
		if (insn.getType() != InsnType.INVOKE || !(insn instanceof InvokeNode)) {
			return false;
		}
		MethodInfo callMethod = ((InvokeNode) insn).getCallMth();
		return "charAt".equals(callMethod.getName())
				&& "java.lang.String".equals(callMethod.getDeclClass().getFullName());
	}

	private static Integer evalConstInt(InsnArg arg) {
		return evalConstInt(arg, 0);
	}

	private static Integer evalConstInt(InsnArg arg, int depth) {
		if (depth > 16) {
			return null;
		}
		if (arg instanceof LiteralArg) {
			return (int) ((LiteralArg) arg).getLiteral();
		}
		if (arg.isInsnWrap()) {
			return evalConstInt(arg.unwrap(), depth + 1);
		}
		if (arg instanceof RegisterArg) {
			return evalConstInt(((RegisterArg) arg).getAssignInsn(), depth + 1);
		}
		return null;
	}

	private static Integer evalConstInt(InsnNode insn, int depth) {
		if (insn == null || depth > 16) {
			return null;
		}
		if (insn.getType() == InsnType.MOVE && insn.getArgsCount() == 1) {
			return evalConstInt(insn.getArg(0), depth + 1);
		}
		if (insn.getType() == InsnType.CONST && insn.getArgsCount() == 1) {
			return evalConstInt(insn.getArg(0), depth + 1);
		}
		if (!(insn instanceof ArithNode)) {
			return null;
		}
		ArithNode arith = (ArithNode) insn;
		List<InsnArg> args = insn.getArgList();
		if (args.isEmpty()) {
			return null;
		}
		Integer first = evalConstInt(args.get(0), depth + 1);
		if (first == null) {
			return null;
		}
		if (args.size() == 1) {
			return first;
		}
		Integer second = evalConstInt(args.get(1), depth + 1);
		if (second == null) {
			return null;
		}
		switch (arith.getOp()) {
			case ADD:
				return first + second;
			case SUB:
				return first - second;
			case MUL:
				return first * second;
			case DIV:
				return second == 0 ? null : first / second;
			case REM:
				return second == 0 ? null : first % second;
			case AND:
				return first & second;
			case OR:
				return first | second;
			case XOR:
				return first ^ second;
			case SHL:
				return first << second;
			case SHR:
				return first >> second;
			case USHR:
				return first >>> second;
			default:
				return null;
		}
	}

	private static String decodeAllatoriString(String str, DecodeKeys keys) {
		int length = str.length();
		char[] chars = new char[length];
		int index = length - 1;
		while (index >= 0) {
			chars[index] = (char) (str.charAt(index) ^ keys.firstKey);
			int prevIndex = index - 1;
			if (prevIndex < 0) {
				break;
			}
			chars[prevIndex] = (char) (str.charAt(prevIndex) ^ keys.secondKey);
			index = prevIndex - 1;
		}
		return new String(chars);
	}

	private static final class DecodeKeys {
		private final int firstKey;
		private final int secondKey;

		private DecodeKeys(int firstKey, int secondKey) {
			this.firstKey = firstKey;
			this.secondKey = secondKey;
		}
	}
}
