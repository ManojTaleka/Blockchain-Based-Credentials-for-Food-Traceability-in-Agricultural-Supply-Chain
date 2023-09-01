from unittest import TestCase

from ..proof import IndyProof, IndyPrimaryProof

INDY_PROOF = {
    "proof": {
        "proofs": [
            {
                "primary_proof": {
                    "eq_proof": {
                        "revealed_attrs": {
                            "legalname": "17452692860386304610406162367026442418073686683521403362495551314143111443652",
                            "sriregdate": "84794510088035165945015616272801238926353986227884872357629651520394786581106",
                        },
                        "a_prime": "32278501255905171704742958460322893511637162983431935430586198860290226716940011148630099119208052729112758092925039150874617283183927448645371882581685088575199866941867151165491046651967119052964806526135854070644719112949280568148440903644904710068267486800869485749248349461501620728165451495601555669946384333482966245666190278766177061903214027961074019726272411064340093147955497074304630819094166118938615860755615625023078371588293961721725584452546589831014718739623649233248030194356309258161615125464664035123726423139356572242556757045992526062527483806001865085714219252862005117598919151259032522148889",
                        "e": "35581451552777769685033243384248421572266001898564008605825317561882904440337036643694472157139199169811306345839082839123770144966895910",
                        "v": "828135525411477722854522947279129529367824493967974661374467145531948008574830974054079283576780714374153012435459948298649103950012856757893702662580316994202540537968066097584782835786817798593382226962016632660559415029091269783131619661150305144161138937512000672990134231506531835018380842894907585523024600357659856760842088978208463181270540996881521313384300664824864197511211768635380758711304109184849426935800528766783989679813547280761825711586667758612892241157731649649671977796509420405204721364323414531438941036273864593005341987433237851455813509580997247737506421671498820538106999006733109420915932517313399525288279220340543074911283732812241240611988838828615608276736374076503183912535082267877825448476018260528143644362338273289271933480597163222466868740551402490479042036399483966063683273100741081681151652755476630114805470239996939074679562728379896561493489436212716612638391498204887984935",
                        "m": {
                            "jurisdictionid": "4688090583250683500407492066026666992233534897866356770488663088356350501628623200115192654864645776575059205900108991424870893822763046867291093307598457278513670200299320511463",
                            "master_secret": "5765990116706384142055090460230893901254240108285092077892244151401046441144630456667590155248838177142351186285450410555444057303439562237518662184356939898507515088151665055566",
                        },
                        "m2": "2119622127109596166553032536805743625111577193704785214102429084853473314741322393298752334122295828925696657072866449946647347230484843925603741440638027",
                    },
                    "ge_proofs": [],
                },
                "non_revoc_proof": {
                    "x_list": {
                        "rho": "1381A1FA6226405CD4D778ECE06598AAE0BE53257E68A6C2B022BAB357ECF06A",
                        "r": "0917CA5871E4FDBB8A2B9897030D2DB42A6C0240B3A58251203773D6E4431A36",
                        "r_prime": "09FB5273DC4220BCB831D50F3E17E1B5BFCA7CA77479E1E055157D7EC2840218",
                        "r_prime_prime": "0DD2B81306168752C811BF02D8898EDDD5271B67D17C42A709579124795A39FA",
                        "r_prime_prime_prime": "0D3CF03C63E9BF905CB4944C5AB14C3B0B07E45AB37FCDEF08132BAB949EAC28",
                        "o": "0780B5E65B610F742577CFECC2BBAC029E89F85888FE4155396AFDA95248FA70",
                        "o_prime": "2167D381A357AD436DA6FF114736DB030F43624E69DFE163E67F95819A949A07",
                        "m": "20420CD1D5D1015F212466A14FB91BDBD9F193010697C7A41A561F22FFA50A73",
                        "m_prime": "0BCEFFDF86A7F99B2BD6FDCF55E5FC8A1AB792B573AC729E62CB9365894FC49F",
                        "t": "121FF75FAF8659D2FAF82A106890EE1A7D55BB97837B75DF04A6EB73E2FADC11",
                        "t_prime": "0D0F7FA1D8D0CDA5CEC6839462449880960EECC5D5BE2492DC784636596B15F5",
                        "m2": "188DF30745A95D0784171FC6C12BA0F1BB8B55AAAB0BFCAA31BE6BAC9FB000F4",
                        "s": "0A5FBEF4E5381FDD3AC873A4C33F0A7CA2F98723C6C277B178EB475DC7F62D2B",
                        "c": "058276E1EEDC087D577006BAF47D620808F05A51523683CD7574007690C8F634",
                    },
                    "c_list": {
                        "e": "6 5D7859942AA7C79B39B184BF6EE34F6DB90FBF13C67CD625582A087AC829CD7E 4 14CDD3630ADC7709CDF0725797887FDBFBF461D78D49547BAE0391D08CD948D4 4 1C5E7F30EC2E00F9270F48EB1FD1ACBBB38FBC57437B92CC1222A627FD38D18B",
                        "d": "6 63C2A154DC37F522876D70D540F8973F139F61B7D9A45CA0ACD4111FC03466FF 4 21C7AE31847BBB8DE7CA65C42618ECD7E9316F12E1B200313D64CD1EB3886920 4 26704886831DC1F7F7BA0798464F79F46C6A71F48DB1CD2E17552E72B4A62D2C",
                        "a": "6 370625C7C0A9B91E90406C632A7094052B59404D939628FF430B41AB5D7631C2 4 43FE8D1FB3DDEF09BF40ED91C560B1BB64C3C7757BE645F57ED73730144E1B4D 4 23FC00129E9331CB517D12B69EBED153164D0A7B50182529D23AC2E44B7601B9",
                        "g": "6 477DE87612F38F4FD17972C138B29E0D6F3B19E00BF51202DF292AA5C7407B18 4 428091929CC1D5BA454AA6E08D2E6E22EA0194318F9A6F725308050EDD6EEE2B 4 345CB5EA0DE020ADA9DAB2D33A032FC43E1ED38EF783C4FBC50EE3259EBD828C",
                        "w": "21 10DE65930CDABB708343BC4698741CE2368AD7678D9E8E92D556617FF9F1C0F82 21 14280B106C12058E5FA8CCC384C4FCB905C0FFCFD775A9D90C8A9B5EADB5F00AF 6 7B727DF8F7763C31916E0500AA4B827D3FE7C8D09F8781EE6D1114610CEE02D2 4 08055D795A3FA8A310CE2D1D35ED4B43483DC30475A340F6AB77E60891AB88D7 6 717DF6D200998E0FC9626D2C6FAB791A9CF1060EA66F55667E1097B5F9D9651A 4 2439CCEE5AEB9018479E2F81E1ACBC97B993A5072EC0454A2C399C876544CF7D",
                        "s": "21 13904BB2C505D54B72C6AEAF1D963B998514D32E529BB8DF3D206EC10D8062E83 21 137621CFF97C9387F55E2261908D4261109C482BD0E0EEC2F0B659FB7C06B5B3F 6 6ADC283E13D215EE2F5FBB6D13CC4A10C433E6C34082F6649CC1475119D53FE0 4 17B097D1FE378BBB570AFB54D2D54A716AF1094A48DB25B1B8E736ECEE1C6A37 6 77BD003ACF6359795E9D5AFC8D2C2F92B5D0B1A17CC8894BD0AD80893DCC3145 4 1A23B81929CF9E9B8F06452E54544A18E96CCD208A9B57BE5C16242291D4F9A1",
                        "u": "21 1244078FABBEC377E653E9A9AA4D440B2629BCFC81BBE5F340F6CCAFF482C5F64 21 141638A50019F7E5C43AEAB9C08A00CA6C7A583CC9E21721637A414563AF99FB9 6 894AE47A984A73C03C35FE26002AB423D880104308CF659EBC802B428474F3D0 4 2FE5FA6F02EF8560B1A110EF469B6931C647A85CD99553FD66F19F0A84860B3D 6 6B224C57D9D733D98C790AAE59788E543F0B601E74332045D6D5A48BD2BB5E78 4 328ED59D6112D424A5F9EB1B53A99A1F1B695C201AAEED9FB5495756902DE885",
                    },
                },
            },
            {
                "primary_proof": {
                    "eq_proof": {
                        "revealed_attrs": {
                            "businesslang": "33232985271439191533377453938110666726604825575392012661293897468349434596941",
                            "legalname": "17452692860386304610406162367026442418073686683521403362495551314143111443652",
                        },
                        "a_prime": "22833405208527909805658627885236743099336730027825383472338187366214272320337675330990871468796305703537931344033496173776963733705008698600674612254082652713935912645330450683745452495876678273146518048789998721046334776140574708429790975677611594817588065443920567166228081407726989775436653333217881175657845993033938320108749200873171887106723038728373011874060294858910535397084640450131604883364402761538578849447322016884121681512954350064697804811600546281829928443200867026343486921907911964121739038205696088198316492988705815389566788346860454163848001286839771027707507085608676234176821335949882609151879",
                        "e": "26211430566728236949472934666404280381429729589602985581360422640738650344423199293303624818679368126760453576661571079887786380504909424",
                        "v": "1183284034125513434526626632453906974024524122355179523163126038427036805660983835291935114724299313011784006409952674194385609314327918950991009227419001790455124235810281676445556361348409120531467227183568063899352946599694953555292292880707030808509851961755055299318374725899096891634542198204148975182963583869495598072844883575645558703940563599413472042728588455433115752776418904275765036927947162756648980766277698357542965839090542945779559326248044767339087391276187923390193967764307014239203880241940667352417447173202287290314079589500282199297479084444031821076350230144839969982651461307607892468488827083453775427345643243839043737086138612353717748072909685557621989119812355961743302809042378983830233918558000415683431547466069557881763682741302771877937684330818471653540484887846945607347348992231866758380480694787988464880611417493797868733007451847225767128713573784142146719971958554655166517625",
                        "m": {
                            "sriregdate": "7575840339790901971126627968837082098626881291739401780806831297827045216866658144901928397498006110265170328305919646086754771869317780632931473346911624167001626838610534568843",
                            "master_secret": "5765990116706384142055090460230893901254240108285092077892244151401046441144630456667590155248838177142351186285450410555444057303439562237518662184356939898507515088151665055566",
                            "jurisdictionid": "14096839792687668090922075920092837277326004351667261353604206746884866410340361120653504934566708275430326153729312326004083085529265517108356327181857586189913372170459175729709",
                        },
                        "m2": "2119622127109596166553032536805743625111577193704785214102429084853473314741325255195002226364320268187061126795878932443225594537196014952825318487949064",
                    },
                    "ge_proofs": [
                        {
                            "u": {
                                "3": "14214025934608562077646947167995470869060367847484688477838543465198741322418093474815111495367149686315148847259831278865241365209384224232954423346984854905942783706673160208640",
                                "2": "14023370669565473291694092130357532707361476334542375350079348190834535906680939872574620435509920568784041847935643881238594980373831048766809683781827213987859676408535849428069",
                                "0": "7342720149800723920049085527885265335922694657934633887893010535330060404347356228131389857905259847481527908547866960993849483727806784544271817532383560767510252739450820430297",
                                "1": "12930108427693598462294132989946197198385148171877437530363114996696998329204786445472597167502572414089948183256933231462127117088661956490732350007130196957027682927664007849658",
                            },
                            "r": {
                                "DELTA": "2276011444312040342177562010127944407206471771850161462011654696029342185527024189779503642466540879503375664970692496221292943337880107380182197681199735646409639460310954096256041883426178537558699617219326605585528418106779400398247492051144494972428159314152305402374525943058962489706836275018074879534905118582562522427229900853927999927959921074680199095872894611297374460046245988175067781594445231402555436922926356352049679447076072906691029517188855451501709086551608514024649309244081422609087275812131326961124014262659223943820640287328415882873680732167765640462280199146540904634993199545501393181617445462059091954661868502783750376727414888895378635536610512795047161770800173743978258282815323798995",
                                "1": "145149166200984508754979331730271650691795059798885849413005398737646540673572796195049028576636858430003736791937280395933429790146358370300465795044845619413090172147042178825796242296189459000963168675142944905821133466353450895170166263470384194507284899124088802588181666362822241089334957725837879453009186865584587784193266176491276610018054057024541423659182491586897069427691457562403438267402863460964331448616927445294885139172523914248218566405910602793346981980875592380295812060121717266020529176064925967534742106030667826236337946961590474915610622834934925872041458052270951297851073431816315266795471496701719035598544703542900159094238036317894294440680846865411989382193271218550053346736524378090",
                                "3": "488242262482251066336600519024239149920945820909803682984138843905329976488753317398237110919606489927089359558153542999969293897450152653769523734260465352344018467036352374271817223858693824706082267934514106409897025269132807613593510744710198445233676405461706854538390095368608374150646804968541094830749611323284157217580822910471203232502232920449193845097941371165010773542220021680961857593548858434528770834197814112784764573149604514968309297299129422430022731158982111734276335932748703841355647540221220235245628861109415553677906418350890407336322231455024554973355128185109292909400204653100022155834264558113422742374787498432051156180056915579661389036207137633808397107069334955079021718840046475740",
                                "0": "1889616213417675662027875323831687679606977901203237164062977174534795712692142405694518356428677653465183695707520741824048628171958421933228302981587300939585899561556164553686639041366495357346706024068593024482876446314389439808067174943877530921644465721688762078031523444351973815942452033520624310772876299834533474980944254684225959838998330440672465002366831279275338579813986121501781838397398509803631315760442180955079109042428151699266385669936917334768811328989734199091636249060358340285444710581471460477163814472432604767781583584634327120526125679621718877544594062397774670136205301735294209068059667059035113840554190788593424842476782037779774100712520753135034354307478795855384146102846291422325",
                                "2": "2256303315125016834439436777492999741791160377376603220468802552504141866513037544234087214702615599485347175200313859812001977863781904875946481595504988017384259236184266088270426514521281378457507050789483814801478499595933999464167811424628487541649424258526511079312011144782002240713571565990349188794909974154062490438204229646615941281994590538687808662516031195951250068887811909625228470867024144015034321118956157816308562072476341838958442831936361331061849739039582311599006782736574367184119332638156053506860974276436399008420893534094538443949848303215619624731404149943675070922177701636329363568655502418065808003716609101369409081151890753329575485528878386404856836884965131088809939644518239521714",
                            },
                            "mj": "14096839792687668090922075920092837277326004351667261353604206746884866410340361120653504934566708275430326153729312326004083085529265517108356327181857586189913372170459175729709",
                            "alpha": "39732014402544066666305752691257351436478792500315973953060895408903156945745295298481231505551106605612400455996248942179005054886204630409163784217146177530904446243078206759306905448438288136897900207969449133498955545726742733646146882695835058150428914834247244807298219323871888394264705707380276719195247948412936421225065274267698430423334359679052053736739609684520324626677167709830296370179401801362973146687673580211321931455713913794645528599190941480829778662321575539160526412685608729405724868316856673561351275842908701968672147908119404226954713721899039602551167566571471365237859825455158944264075087922347837949928215646727196175315950375225785471245890970883732544673245325805751881316942316012048005298720143305095369445267837301634518621030789511255476734017276019872535773209546564817594583596289579731197870049561",
                            "t": {
                                "DELTA": "24507807620968538169926786257196669663829628674945176548989559869833453290754619620752886336680152859587107093453995882927471852312781833873622867489011952726714264538573904721218082147870198466108957261768826812812170727337972103344693646816412861333858987157750482373613343951980503221206042917670615376266085322204366168616039760714683928191729787727342391756728901601834014076830881170568815795080648062044728985406683922625366015906135480407893500533141362120361247547598564354037737202959092025827091301849750648379238398435389516356932367622595223731492389505666326468305427861559849457127890963973993229331775",
                                "2": "76047176608221028468519068489304314238068927063738045321887967648199391545767995466193781936836238600070583986803314771247022831681027057050992136857533056266939849412222984164422800005541618825953123158190447019477513008894322693103132726884636591844788538677508747959148326195695369091593543905012989818594686325738432314327818921040787184442041944415711923150079925346862529052384000072885255838453428376447734488419675582259159543112005228841298206953170182265488107572659064310422482701100783064784028501120021033348231889240639718001161677021014013250819831484739561572871065868606265352688805847775729983323490",
                                "0": "50679642745295171923754683706358400214215498217155467843053196976352383406649124593469550219051236944021392439227799246685393814878606896980505288554698380886315461386392767072850002305225877469317997689653935634475889777757078925967337801390999183907627565604245032760367997623083771902974154252956308592766930461005004633581391988846694633161601793254249152437137771845388433159461685101301008637318307727456090126403781067470287661852382485122721922020212328871373424587102594010853318355840386896946223724584604343345399290890382974188908034054992994126975461059705330501374087167313570051240874831686860535148690",
                                "3": "66928337729696351875172133217609950642698331512240958210447316634445698868251665776819872201185607560694862241492988131882627133504316351013134163298788094339304327928726132791872357561275025379458234234053405489065087803384700395514204215458341958560097080133736340662119856219302296170105994082472398049039676829832979944368411772609308307954514698868126341775937530639178527097257195450374909072450223394668043707074275108199486996243536540009813015336466206178050408983489515950391026045067133630454696849861957051457866759646668437115244581106699290519193884280115629711024195319359748492628008587094999803907922",
                                "1": "16240527026356196137054497550786075095784627443121029704904628658834445965912560629125780050088347057023945024821470223012907572705360383627912546405536939585080156986943699251080108631292150906072925545896153910943611031783144627498463176086496637341332138643393971992105181064495710454434251712758795193299697974135090441014333990840372353673648818587434278396053075776482004040551215221410252915766622684129115640966096470571261130636873342630326061726100141042504104637584319960956869273304261208793038741148332173066892414396252690977873698574706269672026291285492456514196769163274660188030603118109409575042683",
                            },
                            "predicate": {
                                "attr_name": "jurisdictionid",
                                "p_type": "GE",
                                "value": 1,
                            },
                        }
                    ],
                },
                "non_revoc_proof": {
                    "x_list": {
                        "rho": "1F4D25232DBDD4396751A11CCDF58EB92BD3D88C7A9EEA397B31032763FA612A",
                        "r": "1995EA715D057F29E9DF0C00BB94D8E7B3300B89D4AE0AE5FDBE9CC18ACA3C00",
                        "r_prime": "11A611A0C0CF8179C0E454BFE9BD4023FA75EFBE723EF4831EE2B819C8284436",
                        "r_prime_prime": "0C02A6F3A338F0BAECA78B8BAB2F51A18E2E66A1DBEF44305F4B9E986304F039",
                        "r_prime_prime_prime": "194CB95AC8837B5AF27A480BB2677F710C166ACBC76125DBD0972F5D656D708C",
                        "o": "242A0D9550CA19819A4731BADC67A95EB57390E5F63177EB37C777C2D194B857",
                        "o_prime": "0AD930637E1DBABC1A072F00382C64946384025CE423403BDC4B87F1D74C71AE",
                        "m": "24DC7C3E16FEBD6C0F1AE0BA9BCEA64CDDA97CD9C6BBE668371A36136A92BBA1",
                        "m_prime": "2061BF9B182EFECFB26463938BA24C7D2D7367A7F961185EA8AA48B7027F703B",
                        "t": "0A2622F19A15442FCAF3DD5760B1E72312E81FFFDF29348E2B155C6AD5C3314F",
                        "t_prime": "20B3423B69FB4292C3F25C4F2916FCC55F79BAC25FB2E86781705FAA2543151F",
                        "m2": "1EE1B9A6FFD96A061631208FDC0FCFB92B3FCAE9F5E2D68EA9FC9F4ED5FD83B1",
                        "s": "071EBD7E181313D80511D26357DFDA68EFE61FF1E49A197CDDA238BFD919FBF1",
                        "c": "035CC19E347CFF534C05E894BB8132A5E5E734B370724D241D6D3AAA3D0BB1E0",
                    },
                    "c_list": {
                        "e": "6 4ED73798B056F7C18552BD7941052CB983CE664B2E6C4D1FF9C54027D99E0990 4 199AEBA72D16AB760E4F59A39118EB37D7C277A203B9A101EA5E2B6665A0934F 4 2E9DC7AF3BEBD094DC2BBB35EE8DA903876B32AEA2B6FF912290FBB3EEDE29F9",
                        "d": "6 5FCF702955B8D291668F9CE390974551EA5C4C1005F2B51308405539A6EECBFD 4 3B7CA4CAE9CADAFD50EA6086F46D087AA21D8FDCF63642D69FB698B837457649 4 22FF97065821FAEE7EB8C1E43B729286ADFBC3737E9AE6EF8293375ABFDE3419",
                        "a": "6 3AE88157825BC0E106C5CF3C5A93F5A502E22ADEB022D807AF6E2DEC96F6782E 4 0F4C6F27766296E42416F34375BC40C2EB85402DE6A7B7D2AAFF70F37842E6DC 4 0B065C82FF0E7E14DEFC3CA1E11AB41F0FE3C7A42D29FBB0825B370490601590",
                        "g": "6 333B3C68202913B6504F95CA75456E9183177BECDA2664777E3169DAFBC91800 4 23F577FBD5751BC0DC3BE1453758B69ADB2BF7F1F8C2BFB7AC10A7829A97F849 4 0D01A6FC5442DAE3D9960D1846DDA5FE87463B06970840549A517574BECA7D6B",
                        "w": "21 1264C72BBBB93BA1C9E33EEA06B5B7430AE1AD92FEC33AFD31806A3D36EB8D7D4 21 1315520B29BBA556225A889DD94139CF09CBD4AEA52E25F4D2261C96EBC9C387A 6 544948B78028D965166AB0D72EE4F42F5BBFDE696734D2742914A95B4CFE1292 4 1E679EFE7019FFFB99853EF4A7302CD9FCD0A4A4D600E7A3EEE3462D1932E706 6 7DA3017F7ADD0CD6BC5C58706EF39F8F982E35ECA342E6E5CD8D2F9C9C0447C4 4 29DE1EEE64DBD075FFF48C97B94E54543556BEB9A571FFA81F8F40ABC4B1E092",
                        "s": "21 1303A150FE2A205C2E5C41B79FE0FC6BECA41E01395850E09AE2607728A4C325D 21 110BD3B3458D3E9726813C079D41867F5387D6C719E6E8DE8CD6F54AB922233F9 6 755AE2489963E7EA28DE09E84416388F14AD54F854FD948F7317572435BA812E 4 188994E6AF6F0B02E47F1E5D2028BD0ECF12A566BD91B790331DD56CC6BEB3C8 6 5BB8902625C93CA36CFD6BFF797C5C0A91E45B036A7BC82311F2CF045BF6E8CB 4 1ABD443497615B36A6E783BCFF373706E4AE87A0CFAB2C73F9483F8089D2F835",
                        "u": "21 12022CB134154E2750D0B3953FA64E94FB7A80077E40E9FA642F81CA6B1E008F9 21 1176C5A5F3C69FC1BF64DCF6EEC66972F07D5552B773913BF1CF79D03806837B4 6 7F62D3DE296AE18601CA7C0E771C00B1ABFE6247B6547275D08962B29B4D19E1 4 42A100ED48BDF5FA9CD54170AF96B10E76C734A89358BB56680924E232BB6D19 6 5CE5233C06C0A912554CE7C40D8413023481CDDF8DF68EBEB8F27F104661D741 4 033EC06C452DA00A4458E58D2F9D7FEE5394039F98F55B336A09E59CFEAA574B",
                    },
                },
            },
        ],
        "aggregated_proof": {
            "c_hash": "64284694157010500037871584756977982783162678320180085811668324501813312008648",
            "c_list": [[67, 46, 45, 63]],
        },
    },
    "requested_proof": {
        "revealed_attrs": {
            "20_legalname_uuid": {
                "sub_proof_index": 0,
                "raw": "Tart City",
                "encoded": "17452692860386304610406162367026442418073686683521403362495551314143111443652",
            },
            "21_businesslang_uuid": {
                "sub_proof_index": 1,
                "raw": "EN-CA",
                "encoded": "33232985271439191533377453938110666726604825575392012661293897468349434596941",
            },
            "20_sriregdate_uuid": {
                "sub_proof_index": 0,
                "raw": "2019-04-11",
                "encoded": "84794510088035165945015616272801238926353986227884872357629651520394786581106",
            },
            "21_legalname_uuid": {
                "sub_proof_index": 1,
                "raw": "Tart City",
                "encoded": "17452692860386304610406162367026442418073686683521403362495551314143111443652",
            },
        },
        "revealed_attr_groups": {  # this part is a graft to exercise attr groups
            "18_0_uuid": {
                "sub_proof_index": 0,
                "values": {
                    "endDate": {
                        "raw": "",
                        "encoded": "102987336249554097029535212322581322789799900648198034993379397001115665086549",
                    },
                    "id": {"raw": "3", "encoded": "3"},
                    "effectiveDate": {
                        "raw": "2012-12-01",
                        "encoded": "58785836675119218543950531421539993546216494060018521243314445986885543138388",
                    },
                    "jurisdictionId": {"raw": "1", "encoded": "1"},
                    "legalName": {
                        "raw": "Tart City",
                        "encoded": "17452692860386304610406162367026442418073686683521403362495551314143111443652",
                    },
                    "orgTypeId": {"raw": "2", "encoded": "2"},
                    "busId": {"raw": "11144444", "encoded": "11144444"},
                },
            }
        },
        "self_attested_attrs": {},
        "unrevealed_attrs": {},
        "predicates": {"21_jurisdictionid_GE_uuid": {"sub_proof_index": 1}},
    },
    "identifiers": [
        {
            "schema_id": "WgWxqztrNooG92RXvxSTWv:2:sri:1.0",
            "cred_def_id": "WgWxqztrNooG92RXvxSTWv:3:CL:20:tag",
            "rev_reg_id": "WgWxqztrNooG92RXvxSTWv:4:WgWxqztrNooG92RXvxSTWv:3:CL:20:tag:CL_ACCUM:0",
            "timestamp": 1554990827,
        },
        {
            "schema_id": "WgWxqztrNooG92RXvxSTWv:2:sri:1.1",
            "cred_def_id": "WgWxqztrNooG92RXvxSTWv:3:CL:21:tag",
            "rev_reg_id": "WgWxqztrNooG92RXvxSTWv:4:WgWxqztrNooG92RXvxSTWv:3:CL:21:tag:CL_ACCUM:0",
            "timestamp": 1554990827,
        },
    ],
}


class TestIndyProof(TestCase):
    """Test indy proof marshmallow integration."""

    def test_serde(self):
        """Test de/serialization."""
        proof = IndyProof.deserialize(INDY_PROOF)
        assert type(proof) == IndyProof

        proof_dict = proof.serialize()
        assert proof_dict == INDY_PROOF
