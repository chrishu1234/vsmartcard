/* SPDX-License-Identifier: GPL-3.0-or-later */
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.util.*;
import org.jmrtd.lds.icao.*;
/** Original JMRTD 0.8.9 writer. Synthetic optional text and image details. */
public final class GenerateDetailFixtures {
  public static void main(String[] args)throws Exception {
    Path root=Paths.get(args[0]),out=root.resolve("app/src/main/resources/mrtd");
    boolean previewOnly=args.length>1 && args[1].equals("--preview-only");
    for(String format:new String[]{"td1","td3"})for(String auth:new String[]{"bac","pace"}){
      String id=format+"-"+auth;boolean full=format.equals("td1");
      byte[] front=Files.readAllBytes(root.resolve("verification/fixtures/dg5-"+id+".jpg").normalize());
      byte[] rear=Files.readAllBytes(root.resolve("verification/fixtures/dg7-"+id+".jpg").normalize());
      DG11File dg11=new DG11File("ERIKSSON<<ANNA<MARIA / 测试",full?Arrays.asList("TEST ALIAS","测试别名"):null,"TEST-"+id,"19740812",Arrays.asList("TEST CITY","TEST REGION"),
        full?Arrays.asList("TEST STREET 1","TEST CITY"):null,full?"000000000":null,full?"TEST ENGINEER":null,full?"TEST TITLE":null,full?"SYNTHETIC DETAILS ONLY":null,full?rear:null,full?Arrays.asList("TEST-DOC-1","TEST-DOC-2"):null,full?"TEST CUSTODY":null);
      DG12File dg12=new DG12File("TEST AUTHORITY "+format.toUpperCase(),"20240102",full?Arrays.asList("OTHER TEST PERSON"):null,"DEVELOPMENT TEST ONLY",full?"TEST REQUIREMENT":null,full?front:null,full?rear:null,"20240102130405",full?"TEST-DEVICE-001":null);
      if(!previewOnly) {
        Files.write(out.resolve("dg11-"+id+".bin"),dg11.getEncoded());
        Files.write(out.resolve("dg12-"+id+".bin"),dg12.getEncoded());
      }
      // Preview the exact served bytes, including the original parser's normalization.
      DG11File personal=new DG11File(new ByteArrayInputStream(Files.readAllBytes(out.resolve("dg11-"+id+".bin"))));
      DG12File document=new DG12File(new ByteArrayInputStream(Files.readAllBytes(out.resolve("dg12-"+id+".bin"))));
      Files.write(out.resolve("details-preview-"+id+".txt"),preview(personal,document).getBytes(StandardCharsets.UTF_8));
    }
    System.out.println(previewOnly ? "Generated DG11/DG12 previews from existing served files with original JMRTD 0.8.9." : "Generated DG11/DG12 full/partial synthetic details and previews with original JMRTD 0.8.9.");
  }
  private static String preview(DG11File personal,DG12File document) {
    StringBuilder text=new StringBuilder("DG11\n");
    field(text,"Full name",personal.getNameOfHolder());
    field(text,"Other names",personal.getOtherNames());
    field(text,"Personal number",personal.getPersonalNumber());
    field(text,"Full birth date",personal.getFullDateOfBirth());
    field(text,"Place of birth",personal.getPlaceOfBirth());
    field(text,"Address",personal.getPermanentAddress());
    field(text,"Telephone",personal.getTelephone());
    field(text,"Profession",personal.getProfession());
    field(text,"Title",personal.getTitle());
    field(text,"Summary",personal.getPersonalSummary());
    field(text,"Citizenship image",personal.getProofOfCitizenship());
    field(text,"Other documents",personal.getOtherValidTDNumbers());
    field(text,"Custody",personal.getCustodyInformation());
    if(personal.getTagPresenceList().isEmpty()) text.append("No additional fields\n");
    text.append("\nDG12\n");
    field(text,"Issuing authority",document.getIssuingAuthority());
    field(text,"Issue date",document.getDateOfIssue());
    field(text,"Other persons",document.getNamesOfOtherPersons());
    field(text,"Endorsements",document.getEndorsementsAndObservations());
    field(text,"Tax / exit requirements",document.getTaxOrExitRequirements());
    field(text,"Front image",document.getImageOfFront());
    field(text,"Rear image",document.getImageOfRear());
    field(text,"Personalization date/time",document.getDateAndTimeOfPersonalization());
    field(text,"Personalization system",document.getPersonalizationSystemSerialNumber());
    if(document.getTagPresenceList().isEmpty()) text.append("No additional fields\n");
    return text.toString().trim();
  }
  private static void field(StringBuilder text,String label,Object value) {
    if(value==null)return;
    text.append(label).append(": ");
    if(value instanceof byte[]) text.append(((byte[])value).length).append(" bytes");
    else if(value instanceof List<?>) {
      boolean first=true;
      for(Object element:(List<?>)value) { if(!first)text.append(" / "); text.append(element);first=false; }
    } else text.append(value);
    text.append('\n');
  }
}
