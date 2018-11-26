import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CaesarCipherTest {
    @org.junit.jupiter.api.Test
    void encryptRot23() {
        CaesarCipher cipher = new CaesarCipher(23);
        byte cipherText[] = cipher.encrypt("Hi there".getBytes());
        assertEquals("Ef qebob", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRot0() {
        CaesarCipher cipher = new CaesarCipher(0);
        byte cipherText[] = cipher.encrypt("Hi there".getBytes());
        assertEquals("Hi there", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotNegative3() {
        CaesarCipher cipher = new CaesarCipher(-3);
        byte cipherText[] = cipher.encrypt("Hi there".getBytes());
        assertEquals("Ef qebob", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotNegative22() {
        CaesarCipher cipher = new CaesarCipher(-22);
        byte cipherText[] = cipher.encrypt("I like blue".getBytes());
        assertEquals("M pmoi fpyi", new String(cipherText));
    }


    @org.junit.jupiter.api.Test
    void encryptRot26() {
        CaesarCipher cipher = new CaesarCipher(26);
        byte cipherText[] = cipher.encrypt("Hi there".getBytes());
        assertEquals("Hi there", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void decryptRot23() {
        CaesarCipher cipher = new CaesarCipher(23);
        byte cipherText[] = "Ef qebob".getBytes();
        byte plainText[] = cipher.decrypt(cipherText);
        assertEquals("Hi there", new String(plainText));
        // make sure we didn't corrupt the original buffer
        assertEquals("Ef qebob", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void decryptRot0() {
        CaesarCipher cipher = new CaesarCipher(0);
        byte plainText[] = cipher.decrypt("Hi there".getBytes());
        assertEquals("Hi there", new String(plainText));
    }

    @org.junit.jupiter.api.Test
    void decryptRot26() {
        CaesarCipher cipher = new CaesarCipher(26);
        byte plainText[] = cipher.decrypt("Hi there".getBytes());
        assertEquals("Hi there", new String(plainText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLong100() {
        CaesarCipher cipher = new CaesarCipher(100);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("Eb da dwz wjupdejc ykjbezajpewh pk owu, da snkpa ep ej yeldan", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLong2() {
        CaesarCipher cipher = new CaesarCipher(2);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("Kh jg jcf cpavjkpi eqphkfgpvkcn vq uca, jg ytqvg kv kp ekrjgt", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLong10() {
        CaesarCipher cipher = new CaesarCipher(10);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("Sp ro rkn kxidrsxq myxpsnoxdskv dy cki, ro gbydo sd sx mszrob", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLong17() {
        CaesarCipher cipher = new CaesarCipher(17);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("Zw yv yru repkyzex tfewzuvekzrc kf jrp, yv nifkv zk ze tzgyvi", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLong1000() {
        CaesarCipher cipher = new CaesarCipher(1000);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("Ur tq tmp mzkftuzs oazrupqzfumx fa emk, tq idafq uf uz oubtqd", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLongNegative() {
        CaesarCipher cipher = new CaesarCipher(-27);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("He gd gzc zmxsghmf bnmehcdmshzk sn rzx, gd vqnsd hs hm bhogdq", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLong0() {
        CaesarCipher cipher = new CaesarCipher(0);
        byte cipherText[] = cipher.encrypt("If he had anything confidential to say, he wrote it in cipher".getBytes());
        assertEquals("If he had anything confidential to say, he wrote it in cipher", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void encryptRotLonger5() {
        CaesarCipher cipher = new CaesarCipher(5);
        byte cipherText[] = cipher.encrypt("nqqer ffrr f rlr fb ay lzl q rnej gunax lbhs b elb he xv aqg u bhtu fbzrj ungv y ynq iv fr qab g rhas begha ngry l vzh fg er zva q lbhg bgnxr zber p ner jv gu rap e lcgv baern yvfg v pny yl jr zhf g orzh puzbe rpne r shy ar ir eer i rnyg urjbe qfge h pgh er va nar a pvcu rerqg rkgn f vgj rn xr afg u rfrp hevgl vgzn l bgu re jv frn s sbeq vaqrr qvjn f qra vr qn alz b qvph zbscy rnfh e rva qr pv cur e vatl bhera gver y lge na fc ner a gpvc ureab jvzh f gva sb ez lbh g ungv znlun irra p bha gr er qlb h ezlf grevb hfva g rey bp hg ren f gerr gzhfv pvna o lgu ra nz rbs z rqbh neqfc vbat r are bf vg lsb e ovqf zrgbc erfh z rur zr na fna l unez ohguv funo v gbs cy nl vat n arjs natyr qtre z nan pp be qvb a olgu rjvaq bjbs z lfg hq ls vyy f zrjv gunyn ezab g gbz ra gv bag u rnff nhygb azlf r afv ov yv gvr f naqv srnev gvfc b ffv oy rg ung u rvfj bexva tsbe g urs er ap utb i reaz raggb rafh e rgu ng ur vfh a noyr gbvag repr c gbh ep bz zha v pngv bafvf httr f ggu ng gu rar k gbar fubhy qorr a pel cg rq hfv a tnxr ljbeq fhof g vgh gv ba pvc u regu rxrlj beqv f pun en pg rev f rqol zlvav gvny e rzn ex fu rer v albh efnfr irep u nfc fz lc rgv g vbaf gbgur tbir e azr ag sb esh e gure nqina prfg b sva vf ug urq v ssre raprr atva r naq qr ir ybc z lnan ylgvp nyra t var er zn vav t aber qgurq rngu b sgu rx va tyn f glrn enaqg urnp p rff vb ab sbh e arjd hrrai vpgb e vnn aq ur epb e bang vbagu vfwh a run ir ce bir q nqvf genpg vbac r eun cf gu rgh e avat znpuv arjv y yrk pv gr zbe r vagr erfgs ebzy b eqz ry ob hea r naqu vfpno varg ".getBytes());
        assertEquals("svvjw kkww k wqw kg fd qeq v wsjo lzsfc qgmx g jqg mj ca fvl z gmyz kgewo zsla d dsv na kw vfg l wmfx gjlmf slwd q aem kl jw eaf v qgml glscw egjw u sjw oa lz wfu j qhla gfjws dakl a usd dq ow emk l twem uzegj wusj w xmd fw nw jjw n wsdl zwogj vklj m ulm jw af sfw f uahz wjwvl wpls k alo ws cw fkl z wkwu mjalq ales q glz wj oa kws x xgjv afvww vaos k vwf aw vs fqe g vaum egxhd wskm j waf vw ua hzw j afyq gmjwf lajw d qlj sf kh sjw f luah zwjfg oaem k laf xg je qgm l zsla esqzs nwwf u gmf lw jw vqg m jeqk lwjag mkaf l wjd gu ml wjs k ljww lemka uasf t qlz wf se wgx e wvgm sjvkh agfy w fwj gk al qxg j tavk ewlgh jwkm e wzw ew sf ksf q zsje tmlza kzst a lgx hd sq afy s fwox sfydw vywj e sfs uu gj vag f tqlz woafv gogx e qkl mv qx add k ewoa lzsds jefg l lge wf la gfl z wskk smdlg feqk w fka ta da law k sfva xwsja lakh g kka td wl zsl z wako gjcaf yxgj l zwx jw fu zyg n wjfe wfllg wfkm j wlz sl zw akm f stdw lgafl wjuw h lgm ju ge emf a usla gfkak myyw k llz sl lz wfw p lgfw kzgmd vtww f ujq hl wv mka f yscw qogjv kmtk l alm la gf uah z wjlz wcwqo gjva k uzs js ul wja k wvtq eqafa lasd j wes jc kz wjw a fqgm jkskw nwju z skh ke qh wla l agfk lglzw ygnw j few fl xg jxm j lzwj svnsf uwkl g xaf ak zl zwv a xxwj wfuww fyaf w sfv vw nw dgh e qsfs dqlau sdwf y afw jw es afa y fgjw vlzwv wslz g xlz wc af yds k lqws jsfvl zwsu u wkk ag fg xgm j fwoi mwwfn aulg j ass fv zw jug j gfsl agflz akbm f wzs nw hj gnw v svak ljsul agfh w jzs hk lz wlm j fafy esuza fwoa d dwp ua lw egj w aflw jwklx jged g jve wd tg mjf w sfvz akust afwl ", new String(cipherText));
    }


    @org.junit.jupiter.api.Test
    void decryptRot13() {
        CaesarCipher cipher = new CaesarCipher(13);
        byte plainText[] = cipher.decrypt("nqqer ffrr f rlr fb ay lzl q rnej gunax lbhs b elb he xv aqg u bhtu fbzrj ungv y ynq iv fr qab g rhas begha ngry l vzh fg er zva q lbhg bgnxr zber p ner jv gu rap e lcgv baern yvfg v pny yl jr zhf g orzh puzbe rpne r shy ar ir eer i rnyg urjbe qfge h pgh er va nar a pvcu rerqg rkgn f vgj rn xr afg u rfrp hevgl vgzn l bgu re jv frn s sbeq vaqrr qvjn f qra vr qn alz b qvph zbscy rnfh e rva qr pv cur e vatl bhera gver y lge na fc ner a gpvc ureab jvzh f gva sb ez lbh g ungv znlun irra p bha gr er qlb h ezlf grevb hfva g rey bp hg ren f gerr gzhfv pvna o lgu ra nz rbs z rqbh neqfc vbat r are bf vg lsb e ovqf zrgbc erfh z rur zr na fna l unez ohguv funo v gbs cy nl vat n arjs natyr qtre z nan pp be qvb a olgu rjvaq bjbs z lfg hq ls vyy f zrjv gunyn ezab g gbz ra gv bag u rnff nhygb azlf r afv ov yv gvr f naqv srnev gvfc b ffv oy rg ung u rvfj bexva tsbe g urs er ap utb i reaz raggb rafh e rgu ng ur vfh a noyr gbvag repr c gbh ep bz zha v pngv bafvf httr f ggu ng gu rar k gbar fubhy qorr a pel cg rq hfv a tnxr ljbeq fhof g vgh gv ba pvc u regu rxrlj beqv f pun en pg rev f rqol zlvav gvny e rzn ex fu rer v albh efnfr irep u nfc fz lc rgv g vbaf gbgur tbir e azr ag sb esh e gure nqina prfg b sva vf ug urq v ssre raprr atva r naq qr ir ybc z lnan ylgvp nyra t var er zn vav t aber qgurq rngu b sgu rx va tyn f glrn enaqg urnp p rff vb ab sbh e arjd hrrai vpgb e vnn aq ur epb e bang vbagu vfwh a run ir ce bir q nqvf genpg vbac r eun cf gu rgh e avat znpuv arjv y yrk pv gr zbe r vagr erfgs ebzy b eqz ry ob hea r naqu vfpno varg".getBytes());
        assertEquals("addre ssee s eye so nl ymy d earw thank youf o ryo ur ki ndt h ough somew hati l lad vi se dno t eunf ortun atel y imu st re min d yout otake more c are wi th enc r ypti onrea list i cal ly we mus t bemu chmor ecar e ful ne ve rre v ealt hewor dstr u ctu re in ane n ciph eredt exta s itw ea ke nst h esec urity itma y oth er wi sea f ford indee diwa s den ie da nym o dicu mofpl easu r ein de ci phe r ingy ouren tire l ytr an sp are n tcip herno wimu s tin fo rm you t hati mayha veen c oun te re dyo u rmys terio usin t erl oc ut era s tree tmusi cian b yth en am eof m edou ardsp iong e ner os it yfo r bids metop resu m ehe me an san y harm buthi shab i tof pl ay ing a newf angle dger m ana cc or dio n byth ewind owof m yst ud yf ill s mewi thala rmno t tom en ti ont h eass aulto nmys e nsi bi li tie s andi feari tisp o ssi bl et hat h eisw orkin gfor t hef re nc hgo v ernm entto ensu r eth at he isu n able toint erce p tou rc om mun i cati onsis ugge s tth at th ene x tone shoul dbee n cry pt ed usi n gake yword subs t itu ti on cip h erth ekeyw ordi s cha ra ct eri s edby myini tial r ema rk sh ere i nyou rsase verc h asp sm yp eti t ions tothe gove r nme nt fo rfu r ther advan cest o fin is ht hed i ffer encee ngin e and de ve lop m yana lytic alen g ine re ma ini g nore dthed eath o fth ek in gla s tyea randt heac c ess io no fou r newq ueenv icto r iaa nd he rco r onat ionth isju n eha ve pr ove d adis tract ionp e rha ps th etu r ning machi newi l lex ci te mor e inte restf roml o rdm el bo urn e andh iscab inet", new String(plainText));
    }


    @org.junit.jupiter.api.Test
    void decryptRotPositive13() {
        CaesarCipher cipher = new CaesarCipher(13);
        byte plainText[] = cipher.decrypt("addre ssee s eye so nl ymy d earw thank youf o ryo ur ki ndt h ough somew hati l lad vi se dno t eunf ortun atel y imu st re min d yout otake more c are wi th enc r ypti onrea list i cal ly we mus t bemu chmor ecar e ful ne ve rre v ealt hewor dstr u ctu re in ane n ciph eredt exta s itw ea ke nst h esec urity itma y oth er wi sea f ford indee diwa s den ie da nym o dicu mofpl easu r ein de ci phe r ingy ouren ".getBytes());
        assertEquals("nqqer ffrr f rlr fb ay lzl q rnej gunax lbhs b elb he xv aqg u bhtu fbzrj ungv y ynq iv fr qab g rhas begha ngry l vzh fg er zva q lbhg bgnxr zber p ner jv gu rap e lcgv baern yvfg v pny yl jr zhf g orzh puzbe rpne r shy ar ir eer i rnyg urjbe qfge h pgh er va nar a pvcu rerqg rkgn f vgj rn xr afg u rfrp hevgl vgzn l bgu re jv frn s sbeq vaqrr qvjn f qra vr qn alz b qvph zbscy rnfh e rva qr pv cur e vatl bhera ", new String(plainText));
    }

    @org.junit.jupiter.api.Test
    void decryptRotNegative13() {
        CaesarCipher cipher = new CaesarCipher(-13);
        byte plainText[] = cipher.decrypt("addre ssee s eye so nl ymy d earw thank youf o ryo ur ki ndt h ough somew hati l lad vi se dno t eunf ortun atel y imu st re min d yout otake more c are wi th enc r ypti onrea list i cal ly we mus t bemu chmor ecar e ful ne ve rre v ealt hewor dstr u ctu re in ane n ciph eredt exta s itw ea ke nst h esec urity itma y oth er wi sea f ford indee diwa s den ie da nym o dicu mofpl easu r ein de ci phe r ingy ouren ".getBytes());
        assertEquals("nqqer ffrr f rlr fb ay lzl q rnej gunax lbhs b elb he xv aqg u bhtu fbzrj ungv y ynq iv fr qab g rhas begha ngry l vzh fg er zva q lbhg bgnxr zber p ner jv gu rap e lcgv baern yvfg v pny yl jr zhf g orzh puzbe rpne r shy ar ir eer i rnyg urjbe qfge h pgh er va nar a pvcu rerqg rkgn f vgj rn xr afg u rfrp hevgl vgzn l bgu re jv frn s sbeq vaqrr qvjn f qra vr qn alz b qvph zbscy rnfh e rva qr pv cur e vatl bhera ", new String(plainText));
    }

    @org.junit.jupiter.api.Test
    void fullTestNegative17() {
        CaesarCipher cipher = new CaesarCipher(-17);
        byte cipherText[] = "FQNW R ORABC KAXDPQC VH LJC QXVN OAXV CQN QDVJWN BXLRNCH BQN FJB J VJWPH, YRCRODU JWRVJU. BQN FJB BX CQRW CQJC HXD LXDUM LXDWC QNA ENACNKAJN SDBC KH UXXTRWP JC QNA. JYYJANWCUH BQN FJB MNLUJFNM KH QNA YANERXDB XFWNAB, CQNW JKJWMXWNM XA UXBC. BRWLN BQN LXDUMW'C QDWC, BQN WNJAUH BCJAENM. WXC XWUH CQJC, KDC BQN QJM JW JKBLNBB XW XWN QRY. CQN ENCB JC CQN QDVJWN BXLRNCH QJM MAJRWNM RC, KDC RC FJB BCRUU BLJKKH JWM FRCQXDC ODA. BQN QJM J CNAARKUN LXUM, CXX. BQN FJB BWNNIRWP JWM BWROOURWP JWM QNA VNXF FJB SDBC J QXJABN BZDNJT. JWM BQN'M UXBC QJUO QNA CJRU BXVNFQNAN. RWBCNJM XO CJYNARWP PAJLNODUUH, RC QJM J KXWH TWXK JC CQN NWM. (OXLDBNM)".getBytes();
        byte plainText[] = cipher.decrypt(cipherText);
        assertEquals("When I first brought my cat home from the Humane Society she was a mangy, pitiful animal. She was so thin that you could count her vertebrae just by looking at her. Apparently she was declawed by her previous owners, then abandoned or lost. Since she couldn't hunt, she nearly starved. Not only that, but she had an abscess on one hip. The vets at the Humane Society had drained it, but it was still scabby and without fur. She had a terrible cold, too. She was sneezing and sniffling and her meow was just a hoarse squeak. And she'd lost half her tail somewhere. Instead of tapering gracefully, it had a bony knob at the end. (focused)".toUpperCase(), new String(plainText));
        // make sure we didn't corrupt the original buffer
        assertEquals("FQNW R ORABC KAXDPQC VH LJC QXVN OAXV CQN QDVJWN BXLRNCH BQN FJB J VJWPH, YRCRODU JWRVJU. BQN FJB BX CQRW CQJC HXD LXDUM LXDWC QNA ENACNKAJN SDBC KH UXXTRWP JC QNA. JYYJANWCUH BQN FJB MNLUJFNM KH QNA YANERXDB XFWNAB, CQNW JKJWMXWNM XA UXBC. BRWLN BQN LXDUMW'C QDWC, BQN WNJAUH BCJAENM. WXC XWUH CQJC, KDC BQN QJM JW JKBLNBB XW XWN QRY. CQN ENCB JC CQN QDVJWN BXLRNCH QJM MAJRWNM RC, KDC RC FJB BCRUU BLJKKH JWM FRCQXDC ODA. BQN QJM J CNAARKUN LXUM, CXX. BQN FJB BWNNIRWP JWM BWROOURWP JWM QNA VNXF FJB SDBC J QXJABN BZDNJT. JWM BQN'M UXBC QJUO QNA CJRU BXVNFQNAN. RWBCNJM XO CJYNARWP PAJLNODUUH, RC QJM J KXWH TWXK JC CQN NWM. (OXLDBNM)", new String(cipherText));
    }
    @org.junit.jupiter.api.Test
    void fullTestPositive17() {
        CaesarCipher cipher = new CaesarCipher(17);
        byte cipherText[] = "NYVE Z WZIJK SIFLXYK DP TRK YFDV WIFD KYV YLDREV JFTZVKP JYV NRJ R DREXP, GZKZWLC REZDRC. JYV NRJ JF KYZE KYRK PFL TFLCU TFLEK YVI MVIKVSIRV ALJK SP CFFBZEX RK YVI. RGGRIVEKCP JYV NRJ UVTCRNVU SP YVI GIVMZFLJ FNEVIJ, KYVE RSREUFEVU FI CFJK. JZETV JYV TFLCUE'K YLEK, JYV EVRICP JKRIMVU. EFK FECP KYRK, SLK JYV YRU RE RSJTVJJ FE FEV YZG. KYV MVKJ RK KYV YLDREV JFTZVKP YRU UIRZEVU ZK, SLK ZK NRJ JKZCC JTRSSP REU NZKYFLK WLI. JYV YRU R KVIIZSCV TFCU, KFF. JYV NRJ JEVVQZEX REU JEZWWCZEX REU YVI DVFN NRJ ALJK R YFRIJV JHLVRB. REU JYV'U CFJK YRCW YVI KRZC JFDVNYVIV. ZEJKVRU FW KRGVIZEX XIRTVWLCCP, ZK YRU R SFEP BEFS RK KYV VEU. (WFTLJVU)".getBytes();
        byte plainText[] = cipher.decrypt(cipherText);
        assertEquals("when i first brought my cat home from the humane society she was a mangy, pitiful animal. she was so thin that you could count her vertebrae just by looking at her. apparently she was declawed by her previous owners, then abandoned or lost. since she couldn't hunt, she nearly starved. not only that, but she had an abscess on one hip. the vets at the humane society had drained it, but it was still scabby and without fur. she had a terrible cold, too. she was sneezing and sniffling and her meow was just a hoarse squeak. and she'd lost half her tail somewhere. instead of tapering gracefully, it had a bony knob at the end. (focused)".toUpperCase(), new String(plainText));
        // make sure we didn't corrupt the original buffer
        assertEquals("NYVE Z WZIJK SIFLXYK DP TRK YFDV WIFD KYV YLDREV JFTZVKP JYV NRJ R DREXP, GZKZWLC REZDRC. JYV NRJ JF KYZE KYRK PFL TFLCU TFLEK YVI MVIKVSIRV ALJK SP CFFBZEX RK YVI. RGGRIVEKCP JYV NRJ UVTCRNVU SP YVI GIVMZFLJ FNEVIJ, KYVE RSREUFEVU FI CFJK. JZETV JYV TFLCUE'K YLEK, JYV EVRICP JKRIMVU. EFK FECP KYRK, SLK JYV YRU RE RSJTVJJ FE FEV YZG. KYV MVKJ RK KYV YLDREV JFTZVKP YRU UIRZEVU ZK, SLK ZK NRJ JKZCC JTRSSP REU NZKYFLK WLI. JYV YRU R KVIIZSCV TFCU, KFF. JYV NRJ JEVVQZEX REU JEZWWCZEX REU YVI DVFN NRJ ALJK R YFRIJV JHLVRB. REU JYV'U CFJK YRCW YVI KRZC JFDVNYVIV. ZEJKVRU FW KRGVIZEX XIRTVWLCCP, ZK YRU R SFEP BEFS RK KYV VEU. (WFTLJVU)", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void decryptRotNumber() {
        CaesarCipher cipher = new CaesarCipher(12);
        byte plainText[] = cipher.decrypt("12345678910 @%^$%&^&*^&*^*&".getBytes());
        assertEquals("12345678910 @%^$%&^&*^&*^*&", new String(plainText));
    }
    @org.junit.jupiter.api.Test
    void encryptRotNumber() {
        CaesarCipher cipher = new CaesarCipher(23);
        byte cipherText[] = cipher.encrypt("12345678910 @%^$%&^&*^&*^*&".getBytes());
        assertEquals("12345678910 @%^$%&^&*^&*^*&", new String(cipherText));
    }

    @org.junit.jupiter.api.Test
    void fullTest17() {
        CaesarCipher cipher = new CaesarCipher(26);
        byte plainText[] = "NHU LOVE TRAVIS".getBytes();
        byte cipherText[] = cipher.encrypt(plainText);
        assertEquals("NHU LOVE TRAVIS", new String(cipherText));
        byte plainText2[] = cipher.decrypt(cipherText);
        // make sure we didn't corrupt the original buffer
        assertEquals("NHU LOVE TRAVIS", new String(plainText2));
    }

}
