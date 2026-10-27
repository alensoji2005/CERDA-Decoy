const fs=require("fs");
const {Document,Packer,Paragraph,TextRun,AlignmentType}=require("docx");
const F="Times New Roman";
const p=(t,o={})=>new Paragraph({spacing:{line:276,after:o.after??160},alignment:o.align,children:[new TextRun({text:t,font:F,size:24,bold:o.bold,italics:o.italics})]});
const kids=[
 p("28 October 2026"),
 p("Editor-in-Chief, Computers & Security",{after:0}),
 p("Elsevier",{after:240}),
 p("Dear Editor,"),
 p("Please consider the enclosed manuscript, \"Unsupervised threat clustering of SSH and HTTP telemetry via emulated service sandboxes\", as a Full Length Article in Computers & Security."),
 p("Honeypot logs are large and unstructured, and linking sessions to the same operator or tool is difficult. Most earlier work treats the honeypot as a passive recorder. We describe a decoy that varies its own response timing across four regimes and measures the attacker's reaction time net of the delay it injected itself. Each session is reduced to a 64-bit locality-sensitive hash, and sessions within a Hamming-distance threshold are assigned to persistent threat-actor identifiers. We compare a small Transformer encoder with a principal component analysis baseline."),
 p("The evidence in the paper is limited, and we have tried to say so plainly. All results come from a simulator that reproduces the decoy's perturbation schedule and from scripted traffic; no real attacker traffic has been analysed. The two embeddings are close in accuracy on the simulator. They differ in robustness: the baseline tolerates a wider range of clustering thresholds and shorter sessions, while only the Transformer gives hashes that do not change with the batch analysed, which a persistent actor registry requires. We also report that actor assignment depends on arrival order. We believe the measurement method, the findings on hash stability and threshold sensitivity, and the open evaluation toolkit are useful to the journal's readers who run or study honeypots, and we state the missing real-traffic evaluation as the main open question."),
 p("Declarations. The manuscript is original and is not under consideration elsewhere. An earlier form of this work was submitted as an undergraduate project report at Vellore Institute of Technology, which is a thesis in the sense of the journal's policy. Generative AI (Claude, Anthropic) was used in preparing the text, searching the literature and writing parts of the software and analysis scripts; this is declared in the manuscript as the journal requires, and the authors have reviewed and take responsibility for the content. All authors have approved the submission."),
 p("The software and the scripts that produce every result are in a public repository under the MIT licence (https://github.com/alensoji2005/CERDA-Decoy). The version used is the tagged release v1.0.0."),
 p("Sincerely,"),
 p("Alen Varghese Soji, School of Computer Science and Engineering (SCOPE), Vellore Institute of Technology, Vellore 632014, India. Email: alenvarghese.soji2023@vitstudent.ac.in",{after:0}),
];
Packer.toBuffer(new Document({sections:[{properties:{page:{size:{width:11906,height:16838},margin:{top:1440,right:1440,bottom:1440,left:1440}}},children:kids}]})).then(b=>{fs.writeFileSync(process.env.OUT,b);console.log("cover letter",b.length)});
