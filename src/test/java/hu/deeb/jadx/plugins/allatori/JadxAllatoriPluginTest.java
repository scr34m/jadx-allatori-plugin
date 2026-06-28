package hu.deeb.jadx.plugins.allatori;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.objectweb.asm.Opcodes.ACC_PUBLIC;
import static org.objectweb.asm.Opcodes.ACC_STATIC;
import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ARETURN;
import static org.objectweb.asm.Opcodes.ASTORE;
import static org.objectweb.asm.Opcodes.CASTORE;
import static org.objectweb.asm.Opcodes.DUP;
import static org.objectweb.asm.Opcodes.DUP_X1;
import static org.objectweb.asm.Opcodes.DUP_X2;
import static org.objectweb.asm.Opcodes.GETSTATIC;
import static org.objectweb.asm.Opcodes.GOTO;
import static org.objectweb.asm.Opcodes.I2C;
import static org.objectweb.asm.Opcodes.ICONST_1;
import static org.objectweb.asm.Opcodes.ICONST_2;
import static org.objectweb.asm.Opcodes.ICONST_3;
import static org.objectweb.asm.Opcodes.ICONST_4;
import static org.objectweb.asm.Opcodes.ICONST_5;
import static org.objectweb.asm.Opcodes.IFLT;
import static org.objectweb.asm.Opcodes.ILOAD;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
import static org.objectweb.asm.Opcodes.ISHL;
import static org.objectweb.asm.Opcodes.ISTORE;
import static org.objectweb.asm.Opcodes.ISUB;
import static org.objectweb.asm.Opcodes.IXOR;
import static org.objectweb.asm.Opcodes.NEW;
import static org.objectweb.asm.Opcodes.NEWARRAY;
import static org.objectweb.asm.Opcodes.POP;
import static org.objectweb.asm.Opcodes.POP2;
import static org.objectweb.asm.Opcodes.RETURN;
import static org.objectweb.asm.Opcodes.SWAP;
import static org.objectweb.asm.Opcodes.T_CHAR;
import static org.objectweb.asm.Opcodes.V1_8;

class JadxAllatoriPluginTest {

	@Test
	public void integrationTest(@TempDir Path tmpDir) throws Exception {
		File fixtureJar = createAllatoriJvmFixture(tmpDir);

		JadxArgs args = new JadxArgs();
		args.getInputFiles().add(fixtureJar);
		try (JadxDecompiler jadx = new JadxDecompiler(args)) {
			jadx.load();
			JavaClass cls = jadx.getClasses().stream()
					.filter(javaClass -> javaClass.getName().equals("HelloWorld"))
					.findFirst()
					.orElseThrow();
			String clsCode = cls.getCode();
			System.out.println(clsCode);
			assertThat(clsCode).contains("System.out.println(\"[^(a-zA-Z0-9\\\\u4e00-\\\\u9fa5)]\");");
			assertThat(clsCode).contains("System.out.println(\"SX{XP^Y\\u0017D\uffbe\uff89art\");");
			assertThat(clsCode).contains("System.out.println(\"stopAboutTcp_1_\");");
			assertThat(clsCode).doesNotContain("ALLATORIxDEMO");
		}
	}

	private static File createAllatoriJvmFixture(Path tmpDir) throws IOException {
		Path jar = tmpDir.resolve("allatori-jvm-fixture.jar");
		try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
			writeClass(out, "wb.class", buildWbDecryptClass());
			writeClass(out, "pb.class", buildPbDecryptClass());
			writeClass(out, "oc.class", buildOcDecryptClass());
			writeClass(out, "HelloWorld.class", buildHelloWorldClass());
		}
		return jar.toFile();
	}

	private static void writeClass(JarOutputStream out, String name, byte[] data) throws IOException {
		out.putNextEntry(new JarEntry(name));
		out.write(data);
		out.closeEntry();
	}

	private static byte[] buildHelloWorldClass() {
		ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
		cw.visit(V1_8, ACC_PUBLIC, "HelloWorld", null, "java/lang/Object", null);

		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
		mv.visitInsn(RETURN);
		mv.visitMaxs(0, 0);
		mv.visitEnd();

		mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
		mv.visitCode();
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitLdcInsn("\u000b\u001bx$}?\u0011h\nu}|\f0d `u}\u0019%|6$el\r");
		mv.visitMethodInsn(INVOKESTATIC, "wb", "ALLATORIxDEMO", "(Ljava/lang/String;)Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitLdcInsn("'\u001b\u000f\u001b$\u001d-T0\ufffd\ufffd\"\u00067");
		mv.visitMethodInsn(INVOKESTATIC, "pb", "ALLATORIxDEMO", "(Ljava/lang/String;)Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitLdcInsn(";2'6\t$'3<\u0012+6\u0017w\u0017");
		mv.visitMethodInsn(INVOKESTATIC, "oc", "ALLATORIxDEMO", "(Ljava/lang/String;)Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		mv.visitInsn(RETURN);
		mv.visitMaxs(0, 0);
		mv.visitEnd();

		cw.visitEnd();
		return cw.toByteArray();
	}

	private static byte[] buildWbDecryptClass() {
		ClassWriter cw = startDecryptClass("wb");
		MethodVisitor mv = startDecryptMethod(cw);
		emitWbKeySetup(mv);
		finishDecryptMethod(mv);
		return finishClass(cw);
	}

	private static byte[] buildPbDecryptClass() {
		ClassWriter cw = startDecryptClass("pb");
		MethodVisitor mv = startDecryptMethod(cw);
		emitPbKeySetup(mv);
		finishDecryptMethod(mv);
		return finishClass(cw);
	}

	private static byte[] buildOcDecryptClass() {
		ClassWriter cw = startDecryptClass("oc");
		MethodVisitor mv = startDecryptMethod(cw);
		emitOcKeySetup(mv);
		finishDecryptMethod(mv);
		return finishClass(cw);
	}

	private static ClassWriter startDecryptClass(String className) {
		ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
		cw.visit(V1_8, ACC_PUBLIC, className, null, "java/lang/Object", null);

		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
		mv.visitInsn(RETURN);
		mv.visitMaxs(0, 0);
		mv.visitEnd();
		return cw;
	}

	private static MethodVisitor startDecryptMethod(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "ALLATORIxDEMO", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
		mv.visitCode();
		return mv;
	}

	private static void finishDecryptMethod(MethodVisitor mv) {
		mv.visitVarInsn(ALOAD, 0);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
		mv.visitInsn(DUP);
		mv.visitIntInsn(NEWARRAY, T_CHAR);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(DUP);
		mv.visitInsn(POP2);
		mv.visitInsn(SWAP);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(ISUB);
		mv.visitInsn(DUP_X2);
		mv.visitVarInsn(ISTORE, 3);
		mv.visitVarInsn(ASTORE, 1);
		mv.visitVarInsn(ISTORE, 4);
		mv.visitInsn(DUP_X2);
		mv.visitInsn(POP);
		mv.visitVarInsn(ISTORE, 2);
		mv.visitInsn(POP);

		org.objectweb.asm.Label loop = new org.objectweb.asm.Label();
		org.objectweb.asm.Label end = new org.objectweb.asm.Label();
		mv.visitLabel(loop);
		mv.visitJumpInsn(IFLT, end);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitVarInsn(ILOAD, 3);
		mv.visitInsn(DUP_X1);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false);
		mv.visitIincInsn(3, -1);
		mv.visitVarInsn(ILOAD, 2);
		mv.visitInsn(IXOR);
		mv.visitInsn(I2C);
		mv.visitInsn(CASTORE);
		mv.visitVarInsn(ILOAD, 3);
		mv.visitJumpInsn(IFLT, end);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitVarInsn(ILOAD, 3);
		mv.visitIincInsn(3, -1);
		mv.visitInsn(DUP_X1);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false);
		mv.visitVarInsn(ILOAD, 4);
		mv.visitInsn(IXOR);
		mv.visitInsn(I2C);
		mv.visitInsn(CASTORE);
		mv.visitVarInsn(ILOAD, 3);
		mv.visitJumpInsn(GOTO, loop);

		mv.visitLabel(end);
		mv.visitTypeInsn(NEW, "java/lang/String");
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
		mv.visitInsn(ARETURN);
		mv.visitMaxs(0, 0);
		mv.visitEnd();
	}

	private static byte[] finishClass(ClassWriter cw) {
		cw.visitEnd();
		return cw.toByteArray();
	}

	private static void emitWbKeySetup(MethodVisitor mv) {
		mv.visitInsn(ICONST_3);
		mv.visitInsn(ICONST_5);
		mv.visitInsn(IXOR);
		mv.visitInsn(ICONST_3);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(IXOR);

		mv.visitInsn(ICONST_5);
		mv.visitInsn(ICONST_4);
		mv.visitInsn(ISHL);

		mv.visitInsn(ICONST_4);
		mv.visitInsn(DUP);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_5);
		mv.visitInsn(IXOR);
	}

	private static void emitPbKeySetup(MethodVisitor mv) {
		mv.visitInsn(ICONST_2);
		mv.visitInsn(ICONST_5);
		mv.visitInsn(IXOR);
		mv.visitInsn(ICONST_4);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(IXOR);

		mv.visitInsn(ICONST_4);
		mv.visitInsn(DUP);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_3);
		mv.visitInsn(IXOR);

		mv.visitInsn(ICONST_2);
		mv.visitInsn(ICONST_5);
		mv.visitInsn(IXOR);
		mv.visitInsn(ICONST_4);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_2);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(ISHL);
		mv.visitInsn(IXOR);
	}

	private static void emitOcKeySetup(MethodVisitor mv) {
		mv.visitInsn(ICONST_3);
		mv.visitInsn(ICONST_5);
		mv.visitInsn(IXOR);
		mv.visitInsn(ICONST_4);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_2);
		mv.visitInsn(DUP);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_3);
		mv.visitInsn(IXOR);
		mv.visitInsn(IXOR);

		mv.visitInsn(ICONST_4);
		mv.visitInsn(DUP);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_4);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(ISHL);
		mv.visitInsn(IXOR);

		mv.visitInsn(ICONST_4);
		mv.visitInsn(DUP);
		mv.visitInsn(ISHL);
		mv.visitInsn(ICONST_3);
		mv.visitInsn(ICONST_1);
		mv.visitInsn(ISHL);
		mv.visitInsn(IXOR);
	}
}
